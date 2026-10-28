"""Functional contract and exercise containment; security regressions are student work."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sandbox import Sandbox
from service import Shop


class ShopTest(unittest.TestCase):
    def setUp(self):
        self.shop = Shop()
        self.addCleanup(self.shop.close)

    def request(self, method, path, body=None, headers=None):
        with self.shop.lock:
            return self.shop.dispatch(method, path, body or {}, headers or {})

    def login(self, username="alice", password="learn-alice"):
        status, result = self.request("POST", "/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return {"X-Token": result["token"]}

    def test_health_and_catalog(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"status": "ok"}))
        self.assertEqual(self.request("GET", "/products"), (200, {"chair": 5000, "lamp": 1500}))

    def test_wrong_password_rejected(self):
        self.assertEqual(self.request("POST", "/login", {"username": "alice", "password": "wrong"})[0], 401)

    def test_customer_cannot_access_other_customer_data(self):
        alice = self.login()
        self.assertEqual(self.request("GET", "/profile?id=2", headers=alice)[0], 403)
        self.assertEqual(self.request("GET", "/orders", headers=alice)[1], [
            {"id": 1, "owner": 1, "product": "chair", "price": 5000.0}
        ])
        self.assertEqual(self.request("GET", "/files?user=bob&path=receipt.txt", headers=alice)[0], 403)
        self.assertEqual(self.request("GET", "/assistant/context?order_id=2", headers=alice)[0], 404)

    def test_role_header_cannot_grant_staff_access(self):
        alice = self.login()
        self.assertEqual(self.request("GET", "/admin/export", headers={**alice, "X-Role": "staff"})[0], 403)

    def test_order_price_is_taken_from_catalog(self):
        status, order = self.request("POST", "/orders", {
            "product": "lamp", "price": 1
        }, self.login())
        self.assertEqual(status, 201)
        self.assertEqual(order["price"], 1500)

    def test_sql_injection_does_not_bypass_authorization(self):
        alice = self.login()
        self.assertEqual(self.request("GET", "/profile?id=1%20OR%201=1", headers=alice)[0], 400)
        self.assertEqual(self.request("GET", "/assistant/context?order_id=1%20OR%201=1", headers=alice)[0], 400)

    def test_review_html_is_escaped(self):
        self.request("POST", "/reviews", {"product": "chair", "text": "<script>alert(1)</script>"}, self.login())
        body = self.request("GET", "/reviews/view", headers=self.login())[1]
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_assistant_tools_are_authorized(self):
        alice = self.login()
        self.assertEqual(self.request("POST", "/assistant/execute", {}, alice)[0], 400)
        self.assertEqual(self.request("POST", "/assistant/execute", {"decision": {"tool": "read_file", "arguments": []}}, alice)[0], 400)
        self.assertEqual(self.request("POST", "/assistant/execute", {"decision": {"tool": "read_file", "arguments": {}}}, alice)[0], 400)
        dangerous = [
            {"tool": "export_profiles", "arguments": {}},
            {"tool": "delete_tree", "arguments": {"path": "."}},
            {"tool": "read_file", "arguments": {"path": "files/bob/receipt.txt"}},
            {"tool": "read_file", "arguments": {"path": "private/operator-note.txt"}},
            {"tool": "read_file", "arguments": {"path": "files/alice/../bob/receipt.txt"}},
        ]
        for decision in dangerous:
            with self.subTest(decision=decision):
                self.assertEqual(self.request("POST", "/assistant/execute", {"decision": decision}, alice)[0], 403)

    def test_each_assistant_tool_is_checked_for_authenticated_roles(self):
        alice = self.login()
        staff = self.login("staff", "learn-staff")
        self.assertEqual(self.request("POST", "/assistant/execute", {
            "decision": {"tool": "read_file", "arguments": {"path": "files/alice/receipt.txt"}}
        }, staff)[0], 403)
        self.assertEqual(self.request("POST", "/assistant/execute", {
            "decision": {"tool": "export_profiles", "arguments": {}}
        }, staff)[0], 200)
        self.assertEqual(self.request("POST", "/assistant/execute", {
            "decision": {"tool": "unknown", "arguments": {}}
        }, alice)[0], 400)

    def test_debug_logs_require_staff_and_redact_token(self):
        alice = self.login()
        self.assertEqual(self.request("GET", "/debug/logs", headers=alice)[0], 403)
        staff = self.login("staff", "learn-staff")
        status, logs = self.request("GET", "/debug/logs", headers=staff)
        self.assertEqual(status, 200)
        self.assertTrue(all(entry["headers"].get("X-Token") != alice["X-Token"] for entry in logs))

    def test_debug_logs_redact_credentials(self):
        self.login()
        staff = self.login("staff", "learn-staff")
        status, logs = self.request("GET", "/debug/logs", headers=staff)
        self.assertEqual(status, 200)
        login_bodies = [entry["body"] for entry in logs if entry["target"] == "/login"]
        self.assertTrue(login_bodies)
        self.assertTrue(all(body["password"] == "[REDACTED]" for body in login_bodies))
        self.assertTrue(all("learn-alice" not in str(body) and "learn-staff" not in str(body)
                            for body in login_bodies))

    def test_tokens_identify_distinct_users(self):
        alice, bob = self.login(), self.login("bob", "learn-bob")
        self.assertNotEqual(alice, bob)
        self.assertEqual(self.request("GET", "/profile?id=1", headers=alice)[1][0]["name"], "TEST_ALICE")
        self.assertEqual(self.request("GET", "/profile?id=2", headers=bob)[1][0]["name"], "TEST_BOB")

    def test_staff_can_export_with_staff_session(self):
        auth = {**self.login("staff", "learn-staff"), "X-Role": "staff"}
        status, profiles = self.request("GET", "/admin/export", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(len(profiles), 2)

    def test_own_profile_and_receipt(self):
        auth = self.login()
        status, profile = self.request("GET", "/profile?id=1", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(profile[0]["name"], "TEST_ALICE")
        status, receipt = self.request("GET", "/files?user=alice&path=receipt.txt", headers=auth)
        self.assertEqual(status, 200)
        self.assertIn("TEST_ALICE", receipt["content"])

    def test_customer_can_buy_at_catalog_price(self):
        status, order = self.request("POST", "/orders", {"product": "lamp"}, self.login())
        self.assertEqual(status, 201)
        self.assertEqual((order["owner"], order["price"]), (1, 1500))

    def test_unknown_product_rejected(self):
        self.assertEqual(self.request("POST", "/orders", {"product": "unknown"}, self.login())[0], 400)

    def test_review_can_be_submitted_and_viewed(self):
        auth = self.login()
        self.assertEqual(self.request("POST", "/reviews", {"product": "chair", "text": "Comfortable"}, auth)[0], 201)
        self.assertIn("Comfortable", self.request("GET", "/reviews/view", headers=auth)[1])

    def test_assistant_can_return_own_receipt(self):
        auth = self.login()
        status, context = self.request("GET", "/assistant/context?order_id=1", headers=auth)
        self.assertEqual(status, 200)
        self.assertIn("chair", context["prompt"])
        status, result = self.request("POST", "/assistant/execute", {
            "decision": {"tool": "read_file", "arguments": {"path": "files/alice/receipt.txt"}}
        }, auth)
        self.assertEqual(status, 200)
        self.assertIn("TEST_ALICE", result["content"])


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.close)

    def test_parent_paths_cannot_escape_exercise(self):
        for name in ("../../outside.txt", "/etc/passwd"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.sandbox.read(name)

    def test_external_directory_cannot_be_deleted(self):
        with TemporaryDirectory() as directory:
            sentinel = Path(directory) / "sentinel.txt"
            sentinel.write_text("keep")
            with self.assertRaises(ValueError):
                self.sandbox.delete_tree(directory)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_symlink_cannot_escape_exercise(self):
        with TemporaryDirectory() as directory:
            sentinel = Path(directory) / "sentinel.txt"
            sentinel.write_text("keep")
            link = self.sandbox.root / "escape"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.sandbox.read("escape/sentinel.txt")
            with self.assertRaises(ValueError):
                self.sandbox.delete_tree("escape")
            self.assertEqual(sentinel.read_text(), "keep")

    def test_delete_of_fixture_root_stays_inside_exercise(self):
        with TemporaryDirectory() as directory:
            sentinel = Path(directory) / "sentinel.txt"
            sentinel.write_text("keep")
            self.sandbox.delete_tree(".")
            self.assertFalse(self.sandbox.root.exists())
            self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
