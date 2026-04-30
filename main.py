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

    async def publish(self, ev: Event) -> None:
        self._tail.append(ev)
        with contextlib.suppress(asyncio.QueueFull):
            self._q.put_nowait(ev)

    def last(self, n: int = 50) -> list[Event]:
        n = clamp_int(n, 1, 2000)
        return list(self._tail)[-n:]

    async def next(self) -> Event:
        return await self._q.get()


BUS = EventBus()


class WsClient:
    def __init__(self, ws: WebSocket, client_id: str, ip: str | None) -> None:
        self.ws = ws
        self.client_id = client_id
        self.ip = ip
        self.joined_rooms: set[str] = set()


class WsHub:
    def __init__(self) -> None:
        self._clients: dict[str, WsClient] = {}
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, ip: str | None) -> WsClient:
        await ws.accept()
        client_id = short_id("ws")
        c = WsClient(ws, client_id, ip)
        async with self._lock:
            if len(self._clients) >= CFG.max_ws_clients:
                await ws.send_json({"type": "error", "code": "WS_LIMIT", "message": "too many clients"})
                await ws.close(code=1013)
                raise RuntimeError("ws limit")
            self._clients[client_id] = c
        await ws.send_json({"type": "hello", "client_id": client_id, "ts": unix_ts()})
        return c

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            self._clients.pop(client_id, None)

    async def subscribe_room(self, client_id: str, room_code: str) -> None:
        async with self._lock:
            c = self._clients.get(client_id)
            if not c:
                return
            c.joined_rooms.add(room_code)

    async def unsubscribe_room(self, client_id: str, room_code: str) -> None:
        async with self._lock:
            c = self._clients.get(client_id)
            if not c:
                return
            c.joined_rooms.discard(room_code)

    async def broadcast(self, ev: Event) -> None:
        msg = {"type": "event", "kind": ev.kind, "ts": ev.ts, "lobby_id": ev.lobby_id, "payload": ev.payload}
        async with self._lock:
            clients = list(self._clients.values())
        # Best-effort: slow clients won't block
        for c in clients:
            try:
                await c.ws.send_json(msg)
            except Exception:
                with contextlib.suppress(Exception):
                    await c.ws.close()
                await self.disconnect(c.client_id)

    async def broadcast_room(self, room_code: str, ev: Event) -> None:
        msg = {"type": "event", "kind": ev.kind, "ts": ev.ts, "lobby_id": ev.lobby_id, "payload": ev.payload}
        async with self._lock:
            clients = [c for c in self._clients.values() if room_code in c.joined_rooms]
        for c in clients:
            try:
                await c.ws.send_json(msg)
            except Exception:
                with contextlib.suppress(Exception):
                    await c.ws.close()
                await self.disconnect(c.client_id)


HUB = WsHub()


# ============================================================
# Race logic (off-chain mirror)
# ============================================================


def commit_hash(player_addr: str, salt: str, turbo: int, drift: int, sabotage: int) -> str:
    # Mirror the Solidity shape: keccak(player, salt, turbo, drift, sabotage)
    # We use blake2s for deterministic off-chain id; on-chain uses keccak.
    payload = "|".join([normalize_addr(player_addr), salt, str(turbo), str(drift), str(sabotage)]).encode("utf-8")
    return "0x" + keccak_stub_hex(payload)


def make_seed(lobby_id: str, maker: str, taker: str, maker_salt: str | None, taker_salt: str | None) -> int:
    mat = json.dumps(
        {"lid": lobby_id, "m": maker, "t": taker, "ms": maker_salt, "ts": taker_salt, "v": "cm666"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    h = hashlib.blake2b(mat, digest_size=8).digest()
    return int.from_bytes(h, "big") & 0xFFFFFFFF


def move_adjustment(turbo: int, drift: int, sabotage: int, seed: int, maker: bool) -> int:
    s = seed
    volatility = ((s >> (2 if maker else 3)) % 21)
    turbo_gain = turbo * 11
    drift_guard = drift * 7
    drift_cost = drift * 3
    risk = 0
    if turbo > 0 and volatility > (drift_guard // 5):
        risk = (volatility * turbo * 2) // 5
    sabotage_tax = sabotage * 4
    raw = 90 + drift_cost + sabotage_tax + risk
    return max(0, raw - turbo_gain)


def race_times(seed: int, laps: int, track_id: int, m: dict, t_: dict, m_reveal: bool, t_reveal: bool) -> tuple[int, int]:
    base = 420 + laps * 68 + (track_id % 17) * 9
    wobble_a = (seed % 29) * 3
    wobble_b = ((seed >> 5) % 31) * 2
    if m_reveal:
        madj = move_adjustment(m["turbo"], m["drift"], m["sabotage"], seed, True)
    else:
        madj = 120 + ((seed >> 11) % 41)
    if t_reveal:
        tadj = move_adjustment(t_["turbo"], t_["drift"], t_["sabotage"], seed, False)
    else:
        tadj = 120 + ((seed >> 17) % 41)
    m_raw = clamp_int(base + wobble_a + madj, 200, 2400)
    t_raw = clamp_int(base + wobble_b + tadj, 200, 2400)
    if m_reveal and t_reveal:
        m_pen = clamp_int((t_["sabotage"] * 6 + (seed % 7)) // 2, 0, 60)
        t_pen = clamp_int((m["sabotage"] * 6 + ((seed >> 3) % 7)) // 2, 0, 60)
        m_raw = clamp_int(m_raw + m_pen, 200, 2600)
        t_raw = clamp_int(t_raw + t_pen, 200, 2600)
    return m_raw, t_raw


def pick_winner(maker: str, taker: str, m_time: int, t_time: int, m_rev: bool, t_rev: bool, seed: int) -> tuple[str, str]:
    if m_rev and not t_rev:
        return maker, taker
    if t_rev and not m_rev:
        return taker, maker
    if m_time < t_time:
        return maker, taker
    if t_time < m_time:
        return taker, maker
    return (maker, taker) if (seed & 1) == 0 else (taker, maker)


# ============================================================
# Data access helpers
# ============================================================


def row_to_lobby(row: sqlite3.Row) -> LobbyOut:
    return LobbyOut(
        lobby_id=row["lobby_id"],
        room_code=row["room_code"],
        maker_addr=row["maker_addr"],
        taker_addr=row["taker_addr"],
        stake_wei=int(row["stake_wei"]),
        laps=int(row["laps"]),
        track_id=int(row["track_id"]),
        status=LobbyStatus(row["status"]),
        opened_at=int(row["opened_at"]),
        joined_at=row["joined_at"],
        commit_start=row["commit_start"],
        reveal_start=row["reveal_start"],
        maker_commit=row["maker_commit"],
        taker_commit=row["taker_commit"],
        maker_revealed=bool(row["maker_revealed"]),
        taker_revealed=bool(row["taker_revealed"]),
        settle_seed=row["settle_seed"],
        maker_time=row["maker_time"],
        taker_time=row["taker_time"],
        winner_addr=row["winner_addr"],
        fee_wei=row["fee_wei"],
        pot_wei=row["pot_wei"],
    )


def get_lobby(lobby_id: str) -> sqlite3.Row:
    row = DB.execute("SELECT * FROM lobby WHERE lobby_id = ?", (lobby_id,)).fetchone()
    if not row:
        raise ServiceError("NOT_FOUND", "lobby not found", 404)
    return row


def open_lobbies_for_ip(ip: str | None) -> int:
    if not ip:
        return 0
    row = DB.execute(
        "SELECT COUNT(*) AS n FROM lobby WHERE status = 'OPEN' AND opened_at > ?",
        (unix_ts() - 3600,),
    ).fetchone()
    return int(row["n"]) if row else 0


# ============================================================
# FastAPI app
# ============================================================


app = FastAPI(title="ChinaMiun666", version="1.0.0", docs_url="/docs", redoc_url="/redoc")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CFG.cors_allow_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def admin_guard(x_admin_token: str | None = Header(default=None)) -> None:
    if not x_admin_token or not timing_safe_eq(x_admin_token, CFG.admin_token):
        raise http_error("ADMIN_DENIED", "admin token missing/invalid", status=401)


@app.exception_handler(ServiceError)
async def _service_error_handler(_: Request, exc: ServiceError):
    return JSONResponse(status_code=exc.status, content={"code": exc.code, "message": exc.message, **exc.extra})


@app.get("/health")
async def health():
    return {"ok": True, "ts": unix_ts(), "utc": utc_now().isoformat(), "db": os.path.basename(CFG.db_path)}


@app.get("/config", response_model=AdminConfigOut)
async def get_config(_: None = Depends(admin_guard)):
    return AdminConfigOut(
        commit_window_s=CFG.commit_window_s,
        reveal_window_s=CFG.reveal_window_s,
        grace_window_s=CFG.grace_window_s,
        max_ws_clients=CFG.max_ws_clients,
        max_open_lobbies_per_ip=CFG.max_open_lobbies_per_ip,
    )


@app.get("/public")
async def public_info():
    return {
        "service": "ChinaMiun666",
        "ts": unix_ts(),
        "commit_window_s": CFG.commit_window_s,
        "reveal_window_s": CFG.reveal_window_s,
        "grace_window_s": CFG.grace_window_s,
        "cors": CFG.cors_allow_origins,
        "note": "off-chain mirror; on-chain settlement uses RelayBOSS12",
    }


@app.post("/lobbies/open", response_model=LobbyOpenOut)
async def api_open_lobby(payload: LobbyOpenIn, request: Request):
    ip = parse_client_ip(request.headers.get("x-forwarded-for"), getattr(request.client, "host", None))
    if open_lobbies_for_ip(ip) >= CFG.max_open_lobbies_per_ip:
        raise http_error("RATE_LIMIT", "too many open lobbies from this ip", status=429)

    lobby_id = short_id("lob")
    room_code = random_room_code()
    now = unix_ts()

    with tx():
        DB.execute(
            """
            INSERT INTO lobby(
              lobby_id, room_code, maker_addr, stake_wei, laps, track_id, status,
              opened_at, last_event_at
            ) VALUES(?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)
            """,
            (
                lobby_id,
                room_code,
                payload.maker_addr,
                payload.stake_wei,
                payload.laps,
                payload.track_id,
                now,
                now,
            ),
        )
        db_audit("LOBBY_OPEN", ip, lobby_id, payload.maker_addr, payload.model_dump())

    ev = Event("lobby.opened", now, lobby_id, {"room_code": room_code, **payload.model_dump()})
    await BUS.publish(ev)
    await HUB.broadcast(ev)

    return LobbyOpenOut(lobby_id=lobby_id, room_code=room_code, status=LobbyStatus.OPEN, opened_at=now)


@app.get("/lobbies/{lobby_id}", response_model=LobbyOut)
async def api_get_lobby(lobby_id: str):
    row = get_lobby(lobby_id)
    return row_to_lobby(row)


@app.get("/lobbies", response_model=list[LobbyOut])
async def api_list_lobbies(
    status: LobbyStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    if status is None:
        rows = DB.execute("SELECT * FROM lobby ORDER BY opened_at DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = DB.execute(
            "SELECT * FROM lobby WHERE status = ? ORDER BY opened_at DESC LIMIT ?",
            (status.value, limit),
        ).fetchall()
    return [row_to_lobby(r) for r in rows]


@app.post("/lobbies/{lobby_id}/join", response_model=LobbyOut)
async def api_join_lobby(lobby_id: str, payload: LobbyJoinIn, request: Request):
    ip = parse_client_ip(request.headers.get("x-forwarded-for"), getattr(request.client, "host", None))
    now = unix_ts()
    with tx():
        row = get_lobby(lobby_id)
        if row["status"] != "OPEN":
            raise ServiceError("NOT_OPEN", "lobby is not open", 409)
        if normalize_addr(payload.taker_addr) == normalize_addr(row["maker_addr"]):
            raise ServiceError("BAD_INPUT", "maker cannot join own lobby", 400)
        DB.execute(
            """
            UPDATE lobby
            SET taker_addr=?, status='COMMIT', joined_at=?, commit_start=?, last_event_at=?
            WHERE lobby_id=?
            """,
            (payload.taker_addr, now, now, now, lobby_id),
        )
        db_audit("LOBBY_JOIN", ip, lobby_id, payload.taker_addr, payload.model_dump())

    row2 = get_lobby(lobby_id)
    ev = Event("lobby.joined", now, lobby_id, {"lobby_id": lobby_id, "taker_addr": payload.taker_addr})
    await BUS.publish(ev)
    await HUB.broadcast_room(row2["room_code"], ev)
    return row_to_lobby(row2)


@app.post("/lobbies/{lobby_id}/commit", response_model=LobbyOut)
async def api_commit(lobby_id: str, payload: CommitIn, request: Request):
    ip = parse_client_ip(request.headers.get("x-forwarded-for"), getattr(request.client, "host", None))
    now = unix_ts()
    with tx():
        row = get_lobby(lobby_id)
        if row["status"] != "COMMIT":
            raise ServiceError("BAD_STATE", "lobby not in commit", 409)
        if not row["taker_addr"]:
            raise ServiceError("BAD_STATE", "no taker yet", 409)
        if now > int(row["commit_start"]) + CFG.commit_window_s:
            raise ServiceError("TOO_LATE", "commit window expired", 410)

        player = payload.player_addr
        maker = normalize_addr(row["maker_addr"])
        taker = normalize_addr(row["taker_addr"])
        if player not in (maker, taker):
            raise ServiceError("NOT_PLAYER", "address not in lobby", 403)

        if player == maker:
            if row["maker_commit"]:
                raise ServiceError("ALREADY", "maker already committed", 409)
            DB.execute(
                "UPDATE lobby SET maker_commit=?, last_event_at=? WHERE lobby_id=?",
                (payload.commit_hash, now, lobby_id),
            )
        else:
            if row["taker_commit"]:
                raise ServiceError("ALREADY", "taker already committed", 409)
            DB.execute(
                "UPDATE lobby SET taker_commit=?, last_event_at=? WHERE lobby_id=?",
                (payload.commit_hash, now, lobby_id),
            )

        # Transition when both commits in
        row_mid = get_lobby(lobby_id)
        if row_mid["maker_commit"] and row_mid["taker_commit"]:
            DB.execute(
                "UPDATE lobby SET status='REVEAL', reveal_start=?, last_event_at=? WHERE lobby_id=?",
                (now, now, lobby_id),
            )

        db_audit("COMMIT", ip, lobby_id, player, payload.model_dump())

    row2 = get_lobby(lobby_id)
    ev = Event("race.commit", now, lobby_id, {"player_addr": payload.player_addr})
    await BUS.publish(ev)
    await HUB.broadcast_room(row2["room_code"], ev)
    return row_to_lobby(row2)


@app.post("/lobbies/{lobby_id}/reveal", response_model=LobbyOut)
async def api_reveal(lobby_id: str, payload: RevealIn, request: Request):
    ip = parse_client_ip(request.headers.get("x-forwarded-for"), getattr(request.client, "host", None))
    now = unix_ts()
    with tx():
        row = get_lobby(lobby_id)
        if row["status"] != "REVEAL":
            raise ServiceError("BAD_STATE", "lobby not in reveal", 409)
        if now > int(row["reveal_start"]) + CFG.reveal_window_s:
            raise ServiceError("TOO_LATE", "reveal window expired", 410)

        player = payload.player_addr
        maker = normalize_addr(row["maker_addr"])
        taker = normalize_addr(row["taker_addr"] or "")
        if player not in (maker, taker):
            raise ServiceError("NOT_PLAYER", "address not in lobby", 403)

        expected = commit_hash(player, payload.salt, payload.turbo, payload.drift, payload.sabotage)

        if player == maker:
            if int(row["maker_revealed"]) == 1:
                raise ServiceError("ALREADY", "maker already revealed", 409)
            if not row["maker_commit"] or row["maker_commit"].lower() != expected.lower():
                raise ServiceError("MISMATCH", "maker reveal does not match commit", 400)
            DB.execute(
                """
                UPDATE lobby
                SET maker_revealed=1, maker_salt=?, maker_turbo=?, maker_drift=?, maker_sabotage=?, last_event_at=?
                WHERE lobby_id=?
                """,
                (payload.salt, payload.turbo, payload.drift, payload.sabotage, now, lobby_id),
            )
        else:
            if int(row["taker_revealed"]) == 1:
                raise ServiceError("ALREADY", "taker already revealed", 409)
            if not row["taker_commit"] or row["taker_commit"].lower() != expected.lower():
                raise ServiceError("MISMATCH", "taker reveal does not match commit", 400)
            DB.execute(
                """
                UPDATE lobby
                SET taker_revealed=1, taker_salt=?, taker_turbo=?, taker_drift=?, taker_sabotage=?, last_event_at=?
                WHERE lobby_id=?
                """,
                (payload.salt, payload.turbo, payload.drift, payload.sabotage, now, lobby_id),
            )

        db_audit("REVEAL", ip, lobby_id, player, payload.model_dump())

    row2 = get_lobby(lobby_id)
    ev = Event("race.reveal", now, lobby_id, {"player_addr": payload.player_addr})
    await BUS.publish(ev)
    await HUB.broadcast_room(row2["room_code"], ev)
    return row_to_lobby(row2)


@app.post("/lobbies/{lobby_id}/settle", response_model=LobbyOut)
async def api_settle(lobby_id: str, request: Request):
    ip = parse_client_ip(request.headers.get("x-forwarded-for"), getattr(request.client, "host", None))
    now = unix_ts()
    with tx():
        row = get_lobby(lobby_id)
        if row["status"] not in ("REVEAL", "COMMIT"):
            raise ServiceError("BAD_STATE", "lobby not settleable", 409)

        if row["status"] == "COMMIT":
            if now <= int(row["commit_start"]) + CFG.commit_window_s:
                raise ServiceError("TOO_EARLY", "commit still active", 409)
            DB.execute("UPDATE lobby SET status='CANCELLED', last_event_at=? WHERE lobby_id=?", (now, lobby_id))
            db_audit("EXPIRE_COMMIT", ip, lobby_id, None, {"by": "anyone"})
        else:
            # REVEAL
            reveal_start = int(row["reveal_start"])
            maker_rev = bool(row["maker_revealed"])
            taker_rev = bool(row["taker_revealed"])
            both = maker_rev and taker_rev
            expired = now > reveal_start + CFG.reveal_window_s
            if not both and not expired:
                raise ServiceError("TOO_EARLY", "reveal still active", 409)

            maker = normalize_addr(row["maker_addr"])
            taker = normalize_addr(row["taker_addr"] or "")
            seed = make_seed(lobby_id, maker, taker, row["maker_salt"], row["taker_salt"])

            m = {
                "turbo": int(row["maker_turbo"] or 0),
                "drift": int(row["maker_drift"] or 0),
                "sabotage": int(row["maker_sabotage"] or 0),
            }
            t_ = {
                "turbo": int(row["taker_turbo"] or 0),
                "drift": int(row["taker_drift"] or 0),
                "sabotage": int(row["taker_sabotage"] or 0),
            }
            m_time, t_time = race_times(seed, int(row["laps"]), int(row["track_id"]), m, t_, maker_rev, taker_rev)
            winner, loser = pick_winner(maker, taker, m_time, t_time, maker_rev, taker_rev, seed)
            pot = int(row["stake_wei"]) * 2
            fee = (pot * 225) // 10_000

            DB.execute(
                """
                UPDATE lobby
                SET status='SETTLED', settle_seed=?, maker_time=?, taker_time=?, winner_addr=?, pot_wei=?, fee_wei=?, last_event_at=?
                WHERE lobby_id=?
                """,
                (seed, m_time, t_time, winner, pot, fee, now, lobby_id),
            )

            # rating: simplistic, per-season meta
            season = int(db_get_meta("season_id") or "11")
            _rating_apply(season, winner, loser, now)
            db_audit("SETTLE", ip, lobby_id, winner, {"winner": winner, "loser": loser, "seed": seed})

    row2 = get_lobby(lobby_id)
    ev = Event("race.settled", now, lobby_id, {"status": row2["status"], "winner": row2["winner_addr"]})
    await BUS.publish(ev)
    await HUB.broadcast_room(row2["room_code"], ev)
    return row_to_lobby(row2)


def _rating_get(season_id: int, player_addr: str) -> sqlite3.Row:
    row = DB.execute(
        "SELECT * FROM rating WHERE season_id=? AND player_addr=?",
        (season_id, player_addr),
    ).fetchone()
    if not row:
        DB.execute(
            """
            INSERT INTO rating(season_id, player_addr, rating, races, wins, losses, updated_at)
            VALUES(?, ?, 1200, 0, 0, 0, ?)
            """,
            (season_id, player_addr, unix_ts()),
        )
        row = DB.execute(
            "SELECT * FROM rating WHERE season_id=? AND player_addr=?",
            (season_id, player_addr),
        ).fetchone()
    return row


def _rating_apply(season_id: int, winner: str, loser: str, now: int) -> None:
    wrow = _rating_get(season_id, winner)
    lrow = _rating_get(season_id, loser)
    w_old = int(wrow["rating"])
    l_old = int(lrow["rating"])
    diff = abs(w_old - l_old)
    swing = clamp_int(diff // 6, 0, 120)
    w_exp = (6000 + swing) if w_old >= l_old else (6000 - swing)
    l_exp = 10_000 - w_exp
    k = 28
    if int(wrow["races"]) < 6:
        k += 10
    if int(lrow["races"]) < 6:
        k += 10
    k = min(k, 52)
    w_delta = int((k * (10_000 - w_exp)) / 10_000)
    l_delta = -int((k * (10_000 - l_exp)) / 10_000)
    w_new = clamp_int(w_old + w_delta, 700, 2600)
    l_new = clamp_int(l_old + l_delta, 700, 2600)
    DB.execute(
        """
        UPDATE rating SET rating=?, races=races+1, wins=wins+1, updated_at=? WHERE season_id=? AND player_addr=?
        """,
        (w_new, now, season_id, winner),
    )
    DB.execute(
        """
        UPDATE rating SET rating=?, races=races+1, losses=losses+1, updated_at=? WHERE season_id=? AND player_addr=?
        """,
        (l_new, now, season_id, loser),
    )


@app.get("/ratings/{player_addr}", response_model=RatingOut)
async def api_rating(player_addr: str):
    a = normalize_addr(player_addr)
    season = int(db_get_meta("season_id") or "11")
    row = _rating_get(season, a)
    return RatingOut(
        season_id=season,
        player_addr=row["player_addr"],
        rating=int(row["rating"]),
        races=int(row["races"]),
        wins=int(row["wins"]),
        losses=int(row["losses"]),
        updated_at=int(row["updated_at"]),
    )


@app.post("/admin/season/roll")
async def admin_roll_season(_: None = Depends(admin_guard)):
    cur = int(db_get_meta("season_id") or "11")
    nxt = cur + 1
    db_set_meta("season_id", str(nxt))
    return {"ok": True, "previous": cur, "new": nxt, "ts": unix_ts()}


@app.get("/events")
async def api_events(limit: int = Query(default=50, ge=1, le=2000)):
    items = BUS.last(limit)
    return [
        {"kind": e.kind, "ts": e.ts, "lobby_id": e.lobby_id, "payload": e.payload}
        for e in items
    ]


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    peer = getattr(ws.client, "host", None)
    ip = parse_client_ip(ws.headers.get("x-forwarded-for"), peer)
    client = await HUB.connect(ws, ip)
    try:
        while True:
            msg = await ws.receive_text()
            try:
                data = json.loads(msg)
            except Exception:
                await ws.send_json({"type": "error", "code": "BAD_JSON", "message": "invalid json"})
                continue
            op = data.get("op")
            if op == "ping":
                await ws.send_json({"type": "pong", "ts": unix_ts()})
                continue
            if op == "sub":
                room = str(data.get("room_code", "")).strip().upper()
                if len(room) != 6:
                    await ws.send_json({"type": "error", "code": "BAD_ROOM", "message": "room_code must be 6 chars"})
                    continue
                await HUB.subscribe_room(client.client_id, room)
                await ws.send_json({"type": "subscribed", "room_code": room, "ts": unix_ts()})
                continue
            if op == "unsub":
                room = str(data.get("room_code", "")).strip().upper()
                await HUB.unsubscribe_room(client.client_id, room)
                await ws.send_json({"type": "unsubscribed", "room_code": room, "ts": unix_ts()})
                continue
            await ws.send_json({"type": "error", "code": "BAD_OP", "message": "unknown op"})
    except WebSocketDisconnect:
        pass
    finally:
        await HUB.disconnect(client.client_id)


# ============================================================
# Background tasks
# ============================================================


async def event_fanout_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            ev = await asyncio.wait_for(BUS.next(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        with contextlib.suppress(Exception):
            await HUB.broadcast(ev)


async def expiry_sweeper_loop(stop: asyncio.Event) -> None:
    """
    Sweeps old lobbies to CANCELLED if they sit too long in OPEN/COMMIT/REVEAL.
    Keeps the list clean for the UI.
    """
    while not stop.is_set():
        now = unix_ts()
        try:
            # OPEN older than 2 hours -> CANCELLED
            DB.execute(
                "UPDATE lobby SET status='CANCELLED', last_event_at=? WHERE status='OPEN' AND opened_at < ?",
                (now, now - 2 * 3600),
            )
            # COMMIT older than commit_window + 10 minutes -> CANCELLED
            DB.execute(
                """
                UPDATE lobby SET status='CANCELLED', last_event_at=?
                WHERE status='COMMIT' AND commit_start IS NOT NULL AND commit_start < ?
                """,
                (now, now - (CFG.commit_window_s + 600)),
            )
            # REVEAL older than reveal_window + grace + 10 minutes -> allow settle by marking flag via audit only
            DB.execute(
                """
                UPDATE lobby SET last_event_at=?
                WHERE status='REVEAL' AND reveal_start IS NOT NULL AND reveal_start < ?
                """,
                (now, now - (CFG.reveal_window_s + CFG.grace_window_s + 600)),
            )
        except Exception:
            LOG.exception("sweeper failed")
        await asyncio.sleep(5.0)


@app.on_event("startup")
async def _startup():
    logging.basicConfig(
        level=os.environ.get("CHINAMIUN666_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    LOG.info("starting with db=%s port=%s", CFG.db_path, CFG.bind_port)
    stop = asyncio.Event()
    app.state._stop = stop
    app.state._fanout_task = asyncio.create_task(event_fanout_loop(stop))
    app.state._sweep_task = asyncio.create_task(expiry_sweeper_loop(stop))


@app.on_event("shutdown")
async def _shutdown():
    stop: asyncio.Event = getattr(app.state, "_stop", None)
    if stop:
        stop.set()
    for name in ("_fanout_task", "_sweep_task"):
        task = getattr(app.state, name, None)
        if task:
            task.cancel()
            with contextlib.suppress(Exception):
                await task
    with contextlib.suppress(Exception):
        DB.close()


# ============================================================
