"""代理授权服务的本地 HTTP 入口。

回放服务（replay.py）只提供只读事实；本模块在同一组资料上提供核对与
查询接口。除 ``POST /evaluate`` 的试算外，所有接口都是只读的，办理状态
随时间线事件回放得到，接口本身不产生持久副作用。
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlsplit

from .engine import (
    EVT_DESTINATION,
    EVT_ORIGIN,
    HANDOVER,
    READ,
    Engine,
)


def build_handler(engine: Engine):
    class AuthzHandler(BaseHTTPRequestHandler):
        def _send(self, payload, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._send({"error": message}, status)

        def log_message(self, fmt, *args):  # 静默常规访问日志
            return

        def do_GET(self):
            url = urlsplit(self.path)
            qs = parse_qs(url.query)
            path = url.path
            try:
                if path == "/replay":
                    at = _int(qs, "through", None)
                    self._send(engine.replay() if at is None else engine.decisions_through(at))
                elif path == "/effective":
                    self._send(engine.effective_grants(
                        qs["person"][0], qs["site"][0], _int(qs, "at", engine.max_at)))
                elif path == "/survivors":
                    self._send(engine.survivors_after_revocation(
                        qs["grant"][0], _int(qs, "at", None)))
                elif path == "/missing":
                    self._send(engine.missing_confirmations(_int(qs, "at", engine.max_at)))
                elif path == "/receivable":
                    self._send(engine.receivable_transfers(
                        qs["site"][0], _int(qs, "at", engine.max_at)))
                elif path.startswith("/handovers/"):
                    self._send(engine.handover_status(
                        path.removeprefix("/handovers/"), _int(qs, "at", engine.max_at)))
                elif path.startswith("/transfers/"):
                    self._send(engine.transfer_status(
                        path.removeprefix("/transfers/"), _int(qs, "at", engine.max_at)))
                else:
                    self._error(404, "未知接口")
            except KeyError as exc:
                self._error(404, f"对象不存在：{exc.args[0]}")
            except (ValueError, TypeError) as exc:
                self._error(400, str(exc))

        def do_POST(self):
            url = urlsplit(self.path)
            if url.path != "/evaluate":
                self._error(404, "未知接口")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                result = self._evaluate(payload)
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                self._error(400, f"请求无效：{exc}")
                return
            self._send(result)

        def _evaluate(self, p: dict) -> dict:
            """试算一次业务动作；不落库，可重复调用。"""
            at = int(p["at"])
            actor = p["actor"]
            grant_id = p["grant"]
            if "handover_id" in p:
                return engine.evaluate_action(
                    actor, p.get("site", ""), HANDOVER, grant_id, at,
                    handover_id=p["handover_id"])
            if "transfer_id" in p:
                side = EVT_ORIGIN if p.get("side") in ("origin", EVT_ORIGIN) else EVT_DESTINATION
                return engine.evaluate_action(
                    actor, p.get("site", ""), HANDOVER, grant_id, at,
                    transfer_id=p["transfer_id"], side=side,
                    revision=p.get("revision"))
            site = p["site"]
            duty = p.get("duty", READ)
            return engine.evaluate_action(actor, site, duty, grant_id, at)

    return AuthzHandler


def _int(qs: dict, key: str, default):
    if key not in qs:
        return default
    return int(qs[key][0])


def serve(engine: Engine, host: str = "127.0.0.1", port: int = 8766) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), build_handler(engine))
