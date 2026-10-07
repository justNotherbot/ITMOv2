from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
from mcp.server import MCPServer
from sympy import (
    symbols,
    sin,
    cos,
    tan,
    asin,
    acos,
    atan,
    sinh,
    cosh,
    tanh,
    exp as sp_exp,
    log as sp_log,
    sqrt as sp_sqrt,
    Abs,
    sign as sp_sign,
    Piecewise,
)
from sympy.parsing.sympy_parser import parse_expr
from sympy.utilities.lambdify import lambdify


mcp = MCPServer("FourierChebyshev")


# ---- Safe expression evaluation ----
_x = symbols("x")


def _compile_expression(expr: str):
    # Restrict names to x and common safe SymPy functions
    allowed = {
        "x": _x,
        "sin": sin,
        "cos": cos,
        "tan": tan,
        "asin": asin,
        "acos": acos,
        "atan": atan,
        "sinh": sinh,
        "cosh": cosh,
        "tanh": tanh,
        "exp": sp_exp,
        "log": sp_log,
        "sqrt": sp_sqrt,
        "Abs": Abs,
        "abs": Abs,
        "sign": sp_sign,
        "Piecewise": Piecewise,
    }
    parsed = parse_expr(expr, local_dict=allowed, evaluate=True)
    # Map sign to numpy to avoid object arrays
    f = lambdify((_x,), parsed, modules=[{"sign": np.sign}, "numpy"])  # numpy-safe
    return f


# ---- Fourier utilities ----
def _fourier_coefficients_numeric(fn, a: float, b: float, n: int, grid: int):
    # Standard definitions on [a,b]. Let L = (b-a)/2, center c = (a+b)/2.
    # ak = (1/L) ∫ f(x) cos(k*pi*(x-c)/L) dx, bk = (1/L) ∫ f(x) sin(k*pi*(x-c)/L) dx
    # a0 = (1/L) ∫ f(x) dx
    # Series: S(x) = a0/2 + sum_{k=1..n}( ak cos(k*pi*(x-c)/L) + bk sin(...) )
    if not (np.isfinite(a) and np.isfinite(b) and b > a):
        raise ValueError("Invalid domain")
    if not (1 <= n <= 200):
        raise ValueError("n must be between 1 and 200")
    if not (64 <= grid <= (1 << 18)):
        raise ValueError("grid must be between 64 and 262144")

    L = 0.5 * (b - a)
    c = 0.5 * (a + b)
    x = np.linspace(a, b, grid, endpoint=False)
    fx = np.asarray(fn(x), dtype=float)
    if np.any(~np.isfinite(fx)):
        raise ValueError("f(x) produced non-finite values")

    dx = (b - a) / grid

    # Integrals via trapezoid-like Riemann sum (uniform grid)
    a0 = (1.0 / L) * np.sum(fx) * dx

    ak = np.zeros(n + 1)
    bk = np.zeros(n + 1)
    for k in range(1, n + 1):
        arg = (k * math.pi * (x - c) / L)
        ck = np.cos(arg)
        sk = np.sin(arg)
        ak[k] = (1.0 / L) * np.sum(fx * ck) * dx
        bk[k] = (1.0 / L) * np.sum(fx * sk) * dx

    return float(a0), ak[1:].tolist(), bk[1:].tolist()


@mcp.tool()
def fourier_coefficients(
    expression: str,
    domain: Tuple[float, float],
    n: int,
    grid: int | None = None,
) -> dict:
    """Compute Fourier coefficients a0, ak, bk for f(x) over [a,b].

    Normalization:
    L = (b-a)/2. a0=(1/L)∫f, ak=(1/L)∫f cos(kπ(x-c)/L), bk=(1/L)∫f sin(...). c=(a+b)/2.
    Series: S(x)=a0/2+Σ ak cos(...) + bk sin(...).
    """
    a, b = float(domain[0]), float(domain[1])
    if grid is None:
        grid = 4096
    fn = _compile_expression(expression)
    a0, ak, bk = _fourier_coefficients_numeric(fn, a, b, n, grid)
    return {
        "type": "fourier_coefficients",
        "domain": [a, b],
        "n": n,
        "grid": grid,
        "normalization": "a0/ak/bk with 2/L; S=a0/2+Σ(ak cos + bk sin)",
        "a0": a0,
        "ak": ak,
        "bk": bk,
    }


# ---- Chebyshev utilities ----
def _to_t(x: np.ndarray, a: float, b: float) -> np.ndarray:
    return (2.0 * x - (a + b)) / (b - a)


def _chebyshev_coefficients_projection(fn, a: float, b: float, degree: int) -> List[float]:
    # Projection using Gauss-Chebyshev quadrature on t in [-1,1] with weight w(t)=1/sqrt(1-t^2)
    # c_k = (2/π) ∫_{-1}^{1} f(x(t)) T_k(t) / sqrt(1-t^2) dt, with c_0 weighted by (1/π)
    if not (np.isfinite(a) and np.isfinite(b) and b > a):
        raise ValueError("Invalid domain")
    if not (0 <= degree <= 256):
        raise ValueError("degree must be between 0 and 256")

    n = max(128, 2 * (degree + 1))
    k_idx = np.arange(1, n + 1)
    # Gauss-Chebyshev nodes and weights
    t = np.cos((2 * k_idx - 1) * math.pi / (2 * n))
    w = (math.pi / n) * np.ones_like(t)

    # Map to x and evaluate f
    x = 0.5 * ((b - a) * t + (a + b))
    fx = np.asarray(fn(x), dtype=float)
    if np.any(~np.isfinite(fx)):
        raise ValueError("f(x) produced non-finite values")

    # Compute T_k(t) via cos(k arccos t)
    theta = np.arccos(t)
    coeffs = np.zeros(degree + 1)
    # c0
    T0 = np.ones_like(t)
    coeffs[0] = (1.0 / math.pi) * np.sum(w * fx * T0)
    for k in range(1, degree + 1):
        Tk = np.cos(k * theta)
        coeffs[k] = (2.0 / math.pi) * np.sum(w * fx * Tk)
    return coeffs.tolist()


@mcp.tool()
def chebyshev_coefficients(
    expression: str,
    domain: Tuple[float, float],
    degree: int,
    method: str | None = None,
) -> dict:
    """Compute Chebyshev T-basis coefficients for f(x) on [a,b].

    method: "projection" (default). Returns c[0..degree] s.t. p(x)=Σ c_k T_k(t), t mapped from x.
    """
    a, b = float(domain[0]), float(domain[1])
    fn = _compile_expression(expression)
    coeffs = _chebyshev_coefficients_projection(fn, a, b, degree)
    return {
        "type": "chebyshev_coefficients",
        "domain": [a, b],
        "degree": degree,
        "method": (method or "projection"),
        "c": coeffs,
        "mapping": {
            "to_t": "t=(2x-(a+b))/(b-a)",
            "to_x": "x=0.5*((b-a)*t+(a+b))",
        },
    }


if __name__ == "__main__":
    # Default run: stdio transport. For HTTP, prefer `mcp run server.py --transport streamable-http`.
    mcp.run()
