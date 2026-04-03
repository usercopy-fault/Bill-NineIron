#!/usr/bin/env python3
"""TOWER C2 — Entrypoint

Usage:
  python3 main.py server       Start the C2 API server (uvicorn)
  python3 main.py console      Launch the operator console REPL
  python3 main.py bootstrap    Create Gitea repos + webhooks (run once)
"""

import sys
import os


def run_server():
    import uvicorn
    host = os.getenv("C2_HOST", "0.0.0.0")
    port = int(os.getenv("C2_PORT", "8080"))
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        access_log=True,
    )


def run_console():
    from console_ui import CUMMINS320
    CUMMINS320().run()


def run_bootstrap():
    from server import go
    c2_url = os.getenv("C2_EXTERNAL_URL", "http://100.64.0.10:8080")
    results = go.bootstrap(c2_url)
    for repo, r in results.items():
        status = "✓" if r["created"] else "✗"
        webhook = "webhook ✓" if r["webhook"] else "webhook ✗"
        print(f"  {status}  {repo:20s}  {webhook}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "server"

    if cmd == "server":
        run_server()
    elif cmd == "console":
        run_console()
    elif cmd == "bootstrap":
        run_bootstrap()
    else:
        print(__doc__)
        sys.exit(1)
