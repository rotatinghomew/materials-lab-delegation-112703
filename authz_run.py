"""本地代理授权服务启动入口：python3 authz_run.py [--port 8766] [--data data]。"""
import argparse
from pathlib import Path

from authz import Engine
from authz.service import serve

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="线站值班职责代理授权服务")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--data", default=str(ROOT / "data"), help="只读资料目录")
    args = parser.parse_args()
    engine = Engine(args.data)
    with serve(engine, port=args.port) as server:
        print(f"代理授权服务监听 {server.server_address[0]}:{server.server_address[1]}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
