"""Separate gateway credentials; never accept a client-provided identity header."""

import hashlib
import hmac
import re


class GatewayCredentials:
    def __init__(self, clients: list[dict[str, str]]):
        self.clients: list[tuple[str, bytes]] = []
        seen = set()
        for client in clients:
            identity = client.get("identity", "")
            token = client.get("token", "")
            if not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", identity):
                raise ValueError("invalid gateway identity")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
                raise ValueError("gateway token must be 43-128 URL-safe random characters")
            digest = hashlib.sha256(token.encode()).digest()
            if digest in seen:
                raise ValueError("duplicate gateway credential")
            seen.add(digest)
            self.clients.append((identity, digest))
        if not 1 <= len(self.clients) <= 4:
            raise ValueError("configure 1 to 4 gateway clients")

    def __call__(self, headers) -> str | None:
        values = headers.get_all("Authorization", failobj=[])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            return None
        token = values[0][7:]
        if len(token) > 128:
            return None
        digest = hashlib.sha256(token.encode()).digest()
        result = None
        for identity, expected in self.clients:
            if hmac.compare_digest(digest, expected):
                result = identity
        return result
