#!/usr/bin/env python3
"""Host-side TCP forwarder for container -> loopback-only host services.

The observability "infra" services bind 127.0.0.1 on the host (e.g. kind's API
server, Langfuse web). Containers resolve host.docker.internal to the compose
bridge gateway, which has no listener there — so a small proxy on the gateway
forwards to the loopback-bound services.

Usage (usually via run_stack.sh, which starts this automatically):
  python tools/host_forward.py --bind 172.18.0.1 3000:3000 6443:33049
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from typing import Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s forward %(message)s")
logger = logging.getLogger("host_forward")

BACKLOG = 128


def parse_rule(raw: str) -> Tuple[int, int]:
    left, _, right = raw.partition(":")
    if not left or not right:
        raise SystemExit(f"bad rule '{raw}' — expected BINDPORT:DSTPORT")
    return int(left), int(right)


async def _relay(reader, writer) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def _handle(client_reader, client_writer, dst_port: int) -> None:
    try:
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", dst_port)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(
        _relay(client_reader, up_writer),
        _relay(up_reader, client_writer),
    )


async def _serve(bind: str, rules: list[Tuple[int, int]]) -> None:
    servers = []
    for listen_p, dst_p in rules:
        srv = await asyncio.start_server(
            lambda r, w, d=dst_p: _handle(r, w, d),
            host=bind,
            port=listen_p,
            backlog=BACKLOG,
        )
        servers.append(srv)
        logger.info("listening on %s:%s -> 127.0.0.1:%s", bind, listen_p, dst_p)
    stop = asyncio.Future()

    async def _shutdown():
        for s in servers:
            s.close()
            await s.wait_closed()
        stop.set_result(None)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))
        except NotImplementedError:
            pass
    await stop


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="172.18.0.1", help="gateway to bind (host.docker.internal target)")
    parser.add_argument("rules", nargs="+", help="BINDPORT:DSTPORT rules, e.g. 3000:3000 6443:33049")
    args = parser.parse_args()
    rules = [parse_rule(r) for r in args.rules]
    asyncio.run(_serve(args.bind, rules))


if __name__ == "__main__":
    main()