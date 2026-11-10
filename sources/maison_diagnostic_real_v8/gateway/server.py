#!/usr/bin/env python3
"""Loopback-only HTTP server for the simulated read gateway."""

from __future__ import annotations

import argparse
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from gateway.audit import AuditLogger, load_or_create_salt
from gateway.data_source import FixtureDataSource
from gateway.policy import GatewayPolicy
from gateway.service import GatewayService, RateLimiter


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "gateway" / "policy.example.json"
DEFAULT_FIXTURE = ROOT / "gateway" / "fixtures" / "simulated.json"


class GatewayHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 4

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(2)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        request.settimeout(5)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Do not print raw URLs, identity or upstream exceptions on failed requests.
        return


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def handler_factory(service: GatewayService, identity_header: str, authenticate=None):
    unauthenticated = RateLimiter(30)
    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "HAGateway/0.1"
        sys_version = ""

        def _handle(self, send_body: bool = True) -> None:
            self.close_connection = True
            parsed = urlsplit(self.path)
            identities = self.headers.get_all(identity_header, failobj=[])
            identity = identities[0].strip() if len(identities) == 1 else None
            if identity is not None and len(identity) > 200:
                identity = None
            if authenticate is not None:
                identity = authenticate(self.headers)
                if identity is None and parsed.path != "/healthz" and not unauthenticated.allow("all"):
                    self.send_error(429, "Rate limited")
                    return
            try:
                query = parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    max_num_fields=20,
                )
            except ValueError:
                query = {"__invalid_query__": ["1"]}
            if len(self.path) > 2048 or self.headers.get("Transfer-Encoding") or (
                self.headers.get("Content-Length", "0") != "0"
            ):
                query = {"__invalid_query__": ["1"]}
            status, payload = service.handle(
                self.command,
                parsed.path,
                query,
                identity,
            )
            body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_PATCH = _handle
        do_DELETE = _handle
        do_OPTIONS = _handle

        def do_HEAD(self) -> None:
            self._handle(send_body=False)

        def log_message(self, format_string: str, *args: object) -> None:
            return

    return GatewayHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the fixture-only Home Assistant gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--audit-log", type=Path, default=Path("/tmp/ha-gateway-audit.jsonl"))
    parser.add_argument("--audit-salt", type=Path, default=Path("/tmp/ha-gateway-audit.salt"))
    parser.add_argument("--identity-header", default="X-Gateway-Identity")
    args = parser.parse_args()
    if not is_loopback(args.host):
        parser.error("Mission 3 gateway must bind to loopback; use a reviewed Tailscale proxy later")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")

    policy = GatewayPolicy.load(args.policy)
    source = FixtureDataSource(args.fixture)
    audit = AuditLogger(args.audit_log, load_or_create_salt(args.audit_salt))
    service = GatewayService(policy, source, audit)
    server = GatewayHTTPServer((args.host, args.port), handler_factory(service, args.identity_header))
    print(f"Fixture gateway listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
