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
        with contextlib.suppress(Exception):
            ipaddress.ip_address(peer)
            return peer
    return None


class ServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 400, extra: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.extra = extra or {}


def http_error(code: str, message: str, status: int = 400, **extra: t.Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, **extra})


# ============================================================
# Config
# ============================================================


@dataclasses.dataclass(frozen=True)
class AppConfig:
    db_path: str
    bind_host: str
    bind_port: int
    cors_allow_origins: list[str]
    admin_token: str
    session_secret: str
    max_ws_clients: int
    max_open_lobbies_per_ip: int
    commit_window_s: int
    reveal_window_s: int
    grace_window_s: int


def load_config() -> AppConfig:
    root = os.path.dirname(os.path.abspath(__file__))
    db_path = os.environ.get("CHINAMIUN666_DB", os.path.join(root, "chinamiun666.sqlite3"))
    bind_host = os.environ.get("CHINAMIUN666_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("CHINAMIUN666_PORT", "8787"))
    admin_token = os.environ.get("CHINAMIUN666_ADMIN_TOKEN", "adm_" + b32(secrets.token_bytes(18)))
    session_secret = os.environ.get("CHINAMIUN666_SESSION_SECRET", b32(secrets.token_bytes(32)))
    allow_origins_raw = os.environ.get("CHINAMIUN666_CORS", "http://127.0.0.1:8787,http://localhost:8787")
    cors_allow_origins = [o.strip() for o in allow_origins_raw.split(",") if o.strip()]
    max_ws_clients = int(os.environ.get("CHINAMIUN666_MAX_WS", "300"))
    max_open_lobbies_per_ip = int(os.environ.get("CHINAMIUN666_MAX_OPEN_PER_IP", "12"))
    commit_window_s = int(os.environ.get("CHINAMIUN666_COMMIT_WINDOW_S", "420"))
    reveal_window_s = int(os.environ.get("CHINAMIUN666_REVEAL_WINDOW_S", "420"))
    grace_window_s = int(os.environ.get("CHINAMIUN666_GRACE_WINDOW_S", "120"))
    return AppConfig(
        db_path=db_path,
        bind_host=bind_host,
        bind_port=bind_port,
        cors_allow_origins=cors_allow_origins,
        admin_token=admin_token,
        session_secret=session_secret,
        max_ws_clients=max_ws_clients,
        max_open_lobbies_per_ip=max_open_lobbies_per_ip,
        commit_window_s=commit_window_s,
        reveal_window_s=reveal_window_s,
        grace_window_s=grace_window_s,
    )


CFG = load_config()


# ============================================================
# Database
# ============================================================


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lobby (
  lobby_id TEXT PRIMARY KEY,
  room_code TEXT NOT NULL,
  maker_addr TEXT NOT NULL,
  taker_addr TEXT,
  stake_wei INTEGER NOT NULL,
  laps INTEGER NOT NULL,
  track_id INTEGER NOT NULL,
  status TEXT NOT NULL,
  opened_at INTEGER NOT NULL,
  joined_at INTEGER,
  commit_start INTEGER,
  reveal_start INTEGER,
  maker_commit TEXT,
  taker_commit TEXT,
  maker_revealed INTEGER NOT NULL DEFAULT 0,
  taker_revealed INTEGER NOT NULL DEFAULT 0,
  maker_salt TEXT,
  taker_salt TEXT,
  maker_turbo INTEGER,
  maker_drift INTEGER,
  maker_sabotage INTEGER,
  taker_turbo INTEGER,
  taker_drift INTEGER,
  taker_sabotage INTEGER,
  settle_seed INTEGER,
  maker_time INTEGER,
  taker_time INTEGER,
  winner_addr TEXT,
  fee_wei INTEGER,
  pot_wei INTEGER,
  last_event_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lobby_status ON lobby(status, opened_at);
CREATE INDEX IF NOT EXISTS idx_lobby_room ON lobby(room_code);
CREATE INDEX IF NOT EXISTS idx_lobby_maker ON lobby(maker_addr, status);

CREATE TABLE IF NOT EXISTS rating (
  season_id INTEGER NOT NULL,
  player_addr TEXT NOT NULL,
  rating INTEGER NOT NULL,
  races INTEGER NOT NULL,
  wins INTEGER NOT NULL,
  losses INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (season_id, player_addr)
);

CREATE TABLE IF NOT EXISTS audit (
  audit_id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  ip TEXT,
  lobby_id TEXT,
  actor_addr TEXT,
  payload_json TEXT NOT NULL
);
"""

