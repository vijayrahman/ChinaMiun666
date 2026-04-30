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


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(CFG.db_path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


DB = db_connect()


def db_init() -> None:
    for stmt in SCHEMA.split(";"):
        s = stmt.strip()
        if not s:
            continue
        DB.execute(s)
    DB.execute("INSERT OR IGNORE INTO meta(k, v) VALUES('schema_version', '1')")


db_init()


@contextlib.contextmanager
def tx():
    try:
        DB.execute("BEGIN")
        yield
        DB.execute("COMMIT")
    except Exception:
        DB.execute("ROLLBACK")
        raise


def db_get_meta(k: str) -> str | None:
    row = DB.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
    return row["v"] if row else None


def db_set_meta(k: str, v: str) -> None:
    DB.execute("INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


def db_audit(kind: str, ip: str | None, lobby_id: str | None, actor_addr: str | None, payload: dict) -> None:
    DB.execute(
        "INSERT INTO audit(audit_id, ts, kind, ip, lobby_id, actor_addr, payload_json) VALUES(?, ?, ?, ?, ?, ?, ?)",
        (short_id("aud"), unix_ts(), kind, ip, lobby_id, actor_addr, json.dumps(payload, separators=(",", ":"))),
    )


# ============================================================
# Domain models
# ============================================================


class LobbyStatus(str, Enum):
    OPEN = "OPEN"
    COMMIT = "COMMIT"
    REVEAL = "REVEAL"
    SETTLED = "SETTLED"
    CANCELLED = "CANCELLED"


class LobbyOpenIn(BaseModel):
    maker_addr: str = Field(..., description="0x address of maker")
    stake_wei: int = Field(..., ge=1, le=10**21)
    laps: int = Field(..., ge=2, le=24)
    track_id: int = Field(..., ge=1, le=777)

    @field_validator("maker_addr")
    @classmethod
    def _va(cls, v: str) -> str:
        return normalize_addr(v)


class LobbyOpenOut(BaseModel):
    lobby_id: str
    room_code: str
    status: LobbyStatus
    opened_at: int


class LobbyJoinIn(BaseModel):
    taker_addr: str

    @field_validator("taker_addr")
    @classmethod
    def _vb(cls, v: str) -> str:
        return normalize_addr(v)


class CommitIn(BaseModel):
    player_addr: str
    commit_hash: str = Field(..., description="hex string 0x...32 bytes-ish")

    @field_validator("player_addr")
    @classmethod
    def _vc(cls, v: str) -> str:
        return normalize_addr(v)

    @field_validator("commit_hash")
    @classmethod
    def _vd(cls, v: str) -> str:
        x = v.strip()
        if not is_probably_hex(x):
            raise ValueError("commit_hash must be hex")
        return x.lower()


class RevealIn(BaseModel):
    player_addr: str
    salt: str
    turbo: int = Field(..., ge=0, le=10)
    drift: int = Field(..., ge=0, le=10)
    sabotage: int = Field(..., ge=0, le=6)

    @field_validator("player_addr")
    @classmethod
    def _ve(cls, v: str) -> str:
        return normalize_addr(v)

    @field_validator("salt")
    @classmethod
    def _vf(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("salt required")
        if len(s) > 128:
            raise ValueError("salt too long")
        return s


class LobbyOut(BaseModel):
    lobby_id: str
    room_code: str
    maker_addr: str
    taker_addr: str | None
    stake_wei: int
    laps: int
    track_id: int
    status: LobbyStatus
    opened_at: int
    joined_at: int | None
    commit_start: int | None
    reveal_start: int | None
    maker_commit: str | None
    taker_commit: str | None
    maker_revealed: bool
    taker_revealed: bool
    settle_seed: int | None
    maker_time: int | None
    taker_time: int | None
    winner_addr: str | None
    fee_wei: int | None
    pot_wei: int | None


class RatingOut(BaseModel):
    season_id: int
    player_addr: str
    rating: int
    races: int
    wins: int
    losses: int
    updated_at: int


class AdminConfigOut(BaseModel):
    commit_window_s: int
    reveal_window_s: int
    grace_window_s: int
    max_ws_clients: int
    max_open_lobbies_per_ip: int


# ============================================================
# In-memory event bus + WS hub
# ============================================================


@dataclasses.dataclass
class Event:
    kind: str
    ts: int
    lobby_id: str | None
    payload: dict


class EventBus:
    def __init__(self) -> None:
        self._q: "asyncio.Queue[Event]" = asyncio.Queue(maxsize=5000)
        self._tail: deque[Event] = deque(maxlen=2000)

