"""代理授权服务 HTTP 入口的端到端核对。"""
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from authz import Engine
from authz.service import serve
from replay import ROOT


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(ROOT / "data")
        self.server = serve(self.engine, port=0)
        self.worker = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02})
        self.worker.start()
        self.prefix = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.worker.join()
        self.server.server_close()

    def _get(self, path):
        with urlopen(self.prefix + path, timeout=5) as response:
            return json.load(response)

    def _post(self, path, payload):
        req = Request(
            self.prefix + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=5) as response:
                return json.load(response)
        except HTTPError as exc:
            return exc.code, json.load(exc)

    def test_replay_decisions_endpoint(self):
        decisions = self._get("/replay?through=40")
        self.assertTrue(any(d["at"] == 40 and d["allowed"] for d in decisions))
        self.assertFalse(any(d["at"] > 40 for d in decisions))

    def test_effective_and_survivors_endpoints(self):
        rows = self._get("/effective?person=s8&site=east&at=30")
        self.assertEqual({r["grant"] for r in rows}, {"g21", "g22"})
        report = self._get("/survivors?grant=g21&at=41")
        self.assertEqual(set(report["invalidated"]), {"g21", "g23"})
        self.assertIn("west", report["survivors"])

    def test_missing_and_receivable_endpoints(self):
        missing = {m["id"]: m for m in self._get("/missing?at=40")}
        self.assertNotIn("T11", missing)
        self.assertIn("T12", missing)
        west = {r["id"]: r for r in self._get("/receivable?site=west&at=40")}
        self.assertTrue(west["T11"]["receivable"])
        self.assertFalse(west["T12"]["receivable"])

    def test_evaluate_endpoint_denies_and_is_dry_run(self):
        result = self._post("/evaluate", {
            "at": 47, "actor": "s8", "grant": "g22", "handover_id": "H8"})
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "principal_mismatch")
        # 试算不落库：再查 H8 仍是冻结后的 blocked，未新增确认历史。
        hv = self._get("/handovers/H8?at=47")
        self.assertEqual(hv["state"], "blocked")

    def test_evaluate_transfer_independence(self):
        result = self._post("/evaluate", {
            "at": 39, "actor": "s8", "grant": "g26",
            "transfer_id": "T11", "side": "destination", "revision": 1})
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "independence_violation")

    def test_unknown_object_returns_404(self):
        try:
            urlopen(self.prefix + "/handovers/NOPE?at=10", timeout=5)
            self.fail("应当返回 404")
        except HTTPError as exc:
            self.assertEqual(exc.code, 404)
            self.assertIn("对象不存在", json.load(exc)["error"])

    def test_bad_post_returns_400(self):
        code, body = self._post("/evaluate", {"at": "x"})
        self.assertEqual(code, 400)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
