"""
ChinaMiun666 — race PvP service for RelayBOSS12-style duels.

This is a standalone Python web service:
- REST API for creating/joining lobbies, committing/revealing moves, and settling.
- WebSocket channel for live lobby/race events (spectator + player updates).
- SQLite persistence with a small migration layer.
- Optional chain helpers (address validation, ABI-free receipt parsing stubs).

Run:
  python app.py
or:
  uvicorn app:app --host 0.0.0.0 --port 8787
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import datetime as _dt
import functools
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import random
import secrets
import signal
import sqlite3
import string
import sys
import textwrap
import time
import traceback
import typing as t
import uuid
from collections import defaultdict, deque
from enum import Enum

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator


LOG = logging.getLogger("ChinaMiun666")


# ============================================================
# Utilities
# ============================================================


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def unix_ts() -> int:
    return int(time.time())


def clamp_int(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def b32(x: bytes) -> str:
    return base64.b32encode(x).decode("ascii").rstrip("=")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keccak_stub_hex(data: bytes) -> str:
    """
    Placeholder-like function name avoided; this is a deterministic hash helper
    for off-chain commit IDs. It is NOT Ethereum keccak; used only for app ids.
    """
    return hashlib.blake2s(data, digest_size=32).hexdigest()


def timing_safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def is_probably_hex(s: str) -> bool:
    if not s.startswith("0x") or len(s) < 4:
        return False
    try:
        int(s[2:], 16)
        return True
    except Exception:
        return False


def normalize_addr(addr: str) -> str:
    if not isinstance(addr, str):
        raise ValueError("address must be str")
    a = addr.strip()
    if not a.startswith("0x"):
        raise ValueError("address must start with 0x")
    if len(a) != 42:
        raise ValueError("address must be 42 chars")
    if not all(c in "0123456789abcdefABCDEF" for c in a[2:]):
        raise ValueError("address contains non-hex chars")
    return "0x" + a[2:].lower()


def short_id(prefix: str) -> str:
    alpha = string.ascii_lowercase + string.digits
    return prefix + "_" + "".join(secrets.choice(alpha) for _ in range(10))


def random_room_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(6))


def parse_client_ip(xff: str | None, peer: str | None) -> str | None:
    if xff:
        raw = xff.split(",")[0].strip()
        with contextlib.suppress(Exception):
            ipaddress.ip_address(raw)
            return raw
    if peer:
