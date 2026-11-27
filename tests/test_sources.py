"""检查演练来源和本地回放端。"""
import json
import threading
import unittest
from urllib.request import urlopen

from replay import ROOT, ReplayHandler, ThreadingHTTPServer


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.data = {p.stem: json.loads(p.read_bytes()) for p in (ROOT / "data").glob("*.json")}

    def test_replay_source(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
            worker.start()
            try:
                prefix = "http://127.0.0.1:" + str(server.server_port)
                with urlopen(prefix + "/streams", timeout=5) as response:
                    self.assertEqual(set(json.load(response)), set(self.data))
                first = self.data["timeline"][0]
                with urlopen(prefix + "/timeline?through=" + str(first["at"]), timeout=5) as response:
                    events = json.load(response)
                self.assertIn(first, events)
                self.assertLess(len(events), len(self.data["timeline"]))
            finally:
                server.shutdown()
                worker.join()

    def test_source_relationships(self):
        d = self.data
        grants = {r["id"]: r for r in d["grants"]}
        self.assertEqual(grants["g23"]["parent"], "g21")
        self.assertEqual(grants["g21"]["subject"], grants["g22"]["subject"])
        self.assertNotEqual(grants["g21"]["issuer"], grants["g22"]["issuer"])
        affected = next(r for r in d["handover"] if r["id"] == "H8")
        self.assertNotEqual(affected["principal"], grants["g22"]["issuer"])
        self.assertEqual({r["facts"]["actor"] for r in d["timeline"] if r["ref"] == "T11"}, {"s8", "s9"})


if __name__ == "__main__":
    unittest.main()
