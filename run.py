#!/usr/bin/env python3
"""Entry point for the Remote Admin server.

Usage:
    python run.py
    python run.py --port 9000
    SECRET_KEY=your-secret python run.py
"""
import uvicorn
from server.config import HOST, PORT


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Remote Admin Server")
    parser.add_argument("--host", default=HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=PORT, help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    uvicorn.run(
        "server.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
