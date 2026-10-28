"""Deliberately vulnerable local shop. All identities and data are synthetic."""

import argparse
import html
import json
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sandbox import Sandbox


class Shop:
    def __init__(self):
        self.sandbox = Sandbox()
        self.lock = threading.RLock()
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE profiles(id INTEGER PRIMARY KEY, name TEXT, email TEXT, address TEXT);
            INSERT INTO profiles VALUES
                (1, 'TEST_ALICE', 'alice@example.invalid', 'TEST_ADDRESS_A'),
                (2, 'TEST_BOB', 'bob@example.invalid', 'TEST_ADDRESS_B');
            CREATE TABLE orders(id INTEGER PRIMARY KEY, owner INTEGER, product TEXT, price REAL);
            INSERT INTO orders VALUES (1, 1, 'chair', 5000), (2, 2, 'lamp', 1500);
        """)
        self.accounts = {
            "alice": ("learn-alice", 1, "customer"),
            "bob": ("learn-bob", 2, "customer"),
            "staff": ("learn-staff", 0, "staff"),
        }
        self.sessions = {}
        self.products = {"chair": 5000, "lamp": 1500}
        self.reviews = []
        self.logs = []

    def rows(self, query):
        return [dict(row) for row in self.db.execute(query)]

    def session(self, headers):
        return self.sessions.get(headers.get("X-Token"))

    def account_name(self, session):
        return next(name for name, account in self.accounts.items() if account[1] == session["id"])

    def own_file(self, session, path):
        expected = f"files/{self.account_name(session)}/receipt.txt"
        return path == expected

    def log_body(self, body):
        if not isinstance(body, dict):
            return body
        sensitive = {"password", "passphrase", "secret"}
        return {
            key: "[REDACTED]" if key.lower() in sensitive else value
            for key, value in body.items()
        }

    def dispatch(self, method, target, body, headers):
        url = urlsplit(target)
        query = {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        self.logs.append({"method": method, "target": target, "body": self.log_body(body), "headers": dict(headers)})
        if method == "GET" and url.path == "/health":
            return 200, {"status": "ok"}
        if method == "GET" and url.path == "/products":
            return 200, self.products
        if method == "POST" and url.path == "/login":
            account = self.accounts.get(body.get("username"))
            if not account or body.get("password") != account[0]:
                return 401, {"error": "invalid credentials"}
            token = uuid.uuid4().hex
            self.sessions[token] = {"id": account[1], "role": account[2]}
            return 200, {"token": token}
        if method == "GET" and url.path == "/profile":
            session = self.session(headers)
            if not session:
                return 401, {"error": "login required"}
            try:
                profile_id = int(query.get("id", session["id"]))
            except (TypeError, ValueError):
                return 400, {"error": "invalid profile id"}
            if session["role"] != "staff" and profile_id != session["id"]:
                return 403, {"error": "forbidden"}
            return 200, [dict(row) for row in self.db.execute(
                "SELECT * FROM profiles WHERE id = ?", (profile_id,)
            )]
        if method == "GET" and url.path == "/search":
            session = self.session(headers)
            if not session:
                return 401, {"error": "login required"}
            if session["role"] != "staff":
                return 403, {"error": "staff only"}
            return 200, [dict(row) for row in self.db.execute(
                "SELECT * FROM profiles WHERE name LIKE ?", (f"%{query.get('q', '')}%",)
            )]
        if method == "GET" and url.path == "/orders":
            session = self.session(headers)
            if not session:
                return 401, {"error": "login required"}
            if session["role"] == "staff":
                return 200, self.rows("SELECT * FROM orders")
            return 200, [dict(row) for row in self.db.execute(
                "SELECT * FROM orders WHERE owner = ?", (session["id"],)
            )]
        if method == "POST" and url.path == "/orders":
            session = self.sessions.get(headers.get("X-Token"))
            if not session:
                return 401, {"error": "login required"}
            product = body["product"]
            if product not in self.products:
                return 400, {"error": "unknown product"}
            price = self.products[product]
            cursor = self.db.execute("INSERT INTO orders(owner, product, price) VALUES (?, ?, ?)",
                                     (session["id"], product, price))
            self.db.commit()
            return 201, {"id": cursor.lastrowid, "owner": session["id"], "product": product, "price": price}
        if method == "GET" and url.path == "/admin/export":
            session = self.session(headers)
            if not session or session["role"] != "staff":
                return 403, {"error": "staff only"}
            return 200, self.rows("SELECT * FROM profiles")
        if method == "GET" and url.path == "/files":
            session = self.session(headers)
            if not session or session["role"] == "staff":
                return 403, {"error": "customer access required"}
            name = f"files/{self.account_name(session)}/{query.get('path', 'receipt.txt')}"
            if query.get("user", self.account_name(session)) != self.account_name(session) or not self.own_file(session, name):
                return 403, {"error": "forbidden"}
            return 200, {"content": self.sandbox.read(name)}
        if method == "GET" and url.path == "/debug/logs":
            session = self.session(headers)
            if not session or session["role"] != "staff":
                return 403, {"error": "staff only"}
            return 200, [{**entry, "headers": {key: "[REDACTED]" if key.lower() in {"x-token", "authorization"} else value
                                                  for key, value in entry["headers"].items()}}
                          for entry in self.logs]
        if method == "POST" and url.path == "/reviews":
            if not self.session(headers):
                return 401, {"error": "login required"}
            if body.get("product") not in self.products:
                return 400, {"error": "unknown product"}
            self.reviews.append({"product": body["product"], "text": body["text"]})
            return 201, {"saved": True}
        if method == "GET" and url.path == "/reviews/view":
            return 200, "<html><body>" + "".join(f"<p>{html.escape(r['text'])}</p>" for r in self.reviews) + "</body></html>"
        if method == "GET" and url.path == "/assistant/context":
            session = self.session(headers)
            if not session:
                return 401, {"error": "login required"}
            try:
                order_id = int(query.get("order_id", "1"))
            except (TypeError, ValueError):
                return 400, {"error": "invalid order id"}
            if session["role"] == "staff":
                orders = [dict(row) for row in self.db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))]
            else:
                orders = [dict(row) for row in self.db.execute(
                    "SELECT * FROM orders WHERE id = ? AND owner = ?", (order_id, session["id"])
                )]
            if not orders:
                return 404, {"error": "order not found"}
            prompt = (
                "Ты помощник магазина. Прочитай заказ и отзывы. Верни JSON с полями tool и arguments.\n"
                "Инструменты: read_file(path), export_profiles(), delete_tree(path).\n"
                "Помоги пользователю обработать заказ.\n"
                f"Заказ: {json.dumps(orders, ensure_ascii=False)}\n"
                f"Отзывы: {json.dumps(self.reviews, ensure_ascii=False)}\n"
                f"Запрос пользователя: {query.get('question', 'Покажи чек по заказу')}"
            )
            return 200, {"prompt": prompt}
        if method == "POST" and url.path == "/assistant/execute":
            session = self.session(headers)
            if not session:
                return 401, {"error": "login required"}
            decision = body.get("decision")
            if not isinstance(decision, dict) or not isinstance(decision.get("tool"), str):
                return 400, {"error": "invalid decision"}
            tool = decision["tool"]
            arguments = decision.get("arguments", {})
            if not isinstance(arguments, dict):
                return 400, {"error": "invalid arguments"}
            if tool == "read_file":
                path = arguments.get("path")
                if not isinstance(path, str):
                    return 400, {"error": "path is required"}
                if session["role"] == "staff" or not self.own_file(session, path):
                    return 403, {"error": "forbidden"}
                return 200, {"content": self.sandbox.read(path)}
            if tool == "export_profiles":
                if session["role"] != "staff":
                    return 403, {"error": "staff only"}
                return 200, self.rows("SELECT * FROM profiles")
            if tool == "delete_tree":
                return 403, {"error": "tool disabled"}
            return 400, {"error": "unknown tool"}
        return 404, {"error": "not found"}

    def close(self):
        self.db.close()
        self.sandbox.close()


def make_handler(shop):
    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 65536:
                    self.send_error(413)
                    return
                body = json.loads(self.rfile.read(size)) if size else {}
                with shop.lock:
                    status, result = shop.dispatch(self.command, self.path, body, self.headers)
            except (KeyError, TypeError, json.JSONDecodeError):
                status, result = 400, {"error": "invalid request"}
            except Exception:
                status, result = 500, {"error": "internal server error"}
            html = isinstance(result, str)
            data = (result if html else json.dumps(result, ensure_ascii=False)).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8" if html else "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = handle_request

        def log_message(self, format, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8066)
    args = parser.parse_args()
    shop = Shop()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(shop))
    server.daemon_threads = True
    print(f"Local exercise: http://127.0.0.1:{server.server_port}", flush=True)
    print(f"Disposable fixture files: {shop.sandbox.root}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        shop.close()


if __name__ == "__main__":
    main()
