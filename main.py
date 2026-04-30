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
