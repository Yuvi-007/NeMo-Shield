"""Async MongoDB persistence for the NeMo-Shield audit ledger and telemetry.

Uses motor when a MongoDB server is reachable. If motor is missing, the server
cannot be reached, or NEMO_SHIELD_FORCE_MEMORY_DB=1 is set, it falls back to an
in-process dict store so the API (and tests) keep working without a live DB.
"""

from __future__ import annotations

import logging
import math
import os
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger("nemo_shield.database")

DEFAULT_MONGODB_URI = "mongodb://localhost:27017"
DB_NAME = "nemo_shield"
AUDIT_LOGS = "audit_logs"
TELEMETRY_SNAPSHOTS = "telemetry_snapshots"
SERVER_SELECTION_TIMEOUT_MS = 1500

# Latency zones shown on the console gauge: the gateway fast path halts in
# well under 1 ms; a full Colang pass is budgeted at 100 ms.
FAST_PATH_MS = 1.0
COLANG_BUDGET_MS = 100.0

try:
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError:  # pragma: no cover - motor is listed in requirements.txt
    AsyncIOMotorClient = None  # type: ignore[assignment]


def _redact_uri(uri: str) -> str:
    """Hide the password in a MongoDB URI before it is printed."""
    parts = urlsplit(uri)
    if parts.password is None:
        return uri
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit(parts._replace(netloc=f"{parts.username}:****@{host}"))


def _report(message: str, level: int = logging.INFO) -> None:
    """Log and print, so the active backend is visible even without log config."""
    logger.log(level, message)
    print(f"[NeMo-Shield DB] {message}", flush=True)


def _empty_summary() -> Dict[str, Any]:
    return {
        "total_requests": 0,
        "blocked_requests": 0,
        "altered_requests": 0,
        "clean_requests": 0,
        "block_rate_pct": 0.0,
        "avg_latency_ms": 0.0,
        "threat_distribution": {},
        "fast_path_blocks": 0,
        "colang_blocks": 0,
        "sanitized_outputs": 0,
        "p50_latency_ms": 0.0,
        "p99_latency_ms": 0.0,
        "latency_zones": {"under_1ms": 0, "1_to_100ms": 0, "over_100ms": 0},
    }


def nearest_rank_index(count: int, pct: float) -> int:
    """0-based index of the nearest-rank percentile in a sorted list of `count` values."""
    return min(count - 1, max(0, math.ceil(pct / 100 * count) - 1))


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    return round(sorted_values[nearest_rank_index(len(sorted_values), pct)], 2)


def latency_zones(latencies: List[float]) -> Dict[str, int]:
    zones = {"under_1ms": 0, "1_to_100ms": 0, "over_100ms": 0}
    for ms in latencies:
        if ms < FAST_PATH_MS:
            zones["under_1ms"] += 1
        elif ms <= COLANG_BUDGET_MS:
            zones["1_to_100ms"] += 1
        else:
            zones["over_100ms"] += 1
    return zones


def summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute a telemetry summary from raw audit log records."""
    if not records:
        return _empty_summary()
    verdicts = Counter(r.get("verdict") for r in records)
    paths = Counter(r.get("rail_path") for r in records)
    threats = Counter(r["threat_category"] for r in records if r.get("threat_category"))
    latencies = sorted(float(r.get("latency_ms", 0.0)) for r in records)
    total = len(records)
    blocked = verdicts.get("INPUT_BLOCKED", 0)
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "altered_requests": verdicts.get("OUTPUT_ALTERED", 0),
        "clean_requests": verdicts.get("ALLOWED", 0),
        "block_rate_pct": round(blocked / total * 100, 2),
        "avg_latency_ms": round(sum(latencies) / total, 2),
        "threat_distribution": dict(threats),
        "fast_path_blocks": paths.get("FAST_PATH", 0),
        "colang_blocks": paths.get("COLANG_INPUT", 0),
        "sanitized_outputs": verdicts.get("OUTPUT_ALTERED", 0),
        "p50_latency_ms": percentile(latencies, 50),
        "p99_latency_ms": percentile(latencies, 99),
        "latency_zones": latency_zones(latencies),
    }


class AuditStore:
    """Audit/telemetry store backed by MongoDB, or an in-memory dict fallback."""

    def __init__(self) -> None:
        self._client: Any = None
        self._db: Any = None
        self._memory: Dict[str, List[Dict[str, Any]]] = {AUDIT_LOGS: [], TELEMETRY_SNAPSHOTS: []}
        self._connected = False

    @property
    def backend(self) -> str:
        return "mongodb" if self._db is not None else "memory"

    async def connect(self) -> None:
        """Connect to MongoDB once; fall back to memory if unavailable."""
        if self._connected:
            return
        self._connected = True
        if os.getenv("NEMO_SHIELD_FORCE_MEMORY_DB") == "1":
            _report("Using IN-MEMORY audit store (NEMO_SHIELD_FORCE_MEMORY_DB=1).")
            return
        if AsyncIOMotorClient is None:
            _report("Using IN-MEMORY audit store (motor is not installed).", logging.WARNING)
            return
        uri = os.getenv("MONGODB_URI")
        source = "MONGODB_URI" if uri else "default"
        uri = uri or DEFAULT_MONGODB_URI
        safe_uri = _redact_uri(uri)
        try:
            client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS)
            await client.admin.command("ping")
        except Exception as exc:  # noqa: BLE001 - any connection failure triggers fallback
            _report(
                f"MongoDB unreachable at {safe_uri} ({source}): {exc}. "
                "FELL BACK to IN-MEMORY audit store; data will not persist.",
                logging.WARNING,
            )
            return
        self._client = client
        self._db = client[DB_NAME]
        await self._db[AUDIT_LOGS].create_index("timestamp")
        await self._db[AUDIT_LOGS].create_index("verdict")
        # Percentiles sort by latency; the index keeps that off an in-memory sort.
        await self._db[AUDIT_LOGS].create_index("latency_ms")
        _report(f"Connected to LIVE MongoDB at {safe_uri} ({source}), database '{DB_NAME}'.")

    async def close(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None
        self._db = None
        self._connected = False

    async def insert_audit_log(self, entry: Dict[str, Any]) -> None:
        await self.connect()
        if self._db is not None:
            try:
                await self._db[AUDIT_LOGS].insert_one(dict(entry))
                return
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to write audit log to MongoDB (%s); kept in memory.", exc)
        self._memory[AUDIT_LOGS].append(dict(entry))

    async def find_audit_logs(
        self, limit: int = 50, skip: int = 0, verdict: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        await self.connect()
        query: Dict[str, Any] = {"verdict": verdict} if verdict else {}
        if self._db is not None:
            cursor = (
                self._db[AUDIT_LOGS]
                .find(query, {"_id": 0})
                .sort("timestamp", -1)
                .skip(skip)
                .limit(limit)
            )
            return await cursor.to_list(length=limit)
        records = [r for r in self._memory[AUDIT_LOGS] if not verdict or r.get("verdict") == verdict]
        records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return records[skip : skip + limit]

    async def telemetry_summary(self) -> Dict[str, Any]:
        await self.connect()
        if self._db is None:
            return summarize_records(self._memory[AUDIT_LOGS])
        pipeline = [
            {
                "$facet": {
                    "totals": [
                        {
                            "$group": {
                                "_id": None,
                                "total": {"$sum": 1},
                                "blocked": {"$sum": {"$cond": [{"$eq": ["$verdict", "INPUT_BLOCKED"]}, 1, 0]}},
                                "altered": {"$sum": {"$cond": [{"$eq": ["$verdict", "OUTPUT_ALTERED"]}, 1, 0]}},
                                "clean": {"$sum": {"$cond": [{"$eq": ["$verdict", "ALLOWED"]}, 1, 0]}},
                                "fast_path": {"$sum": {"$cond": [{"$eq": ["$rail_path", "FAST_PATH"]}, 1, 0]}},
                                "colang": {"$sum": {"$cond": [{"$eq": ["$rail_path", "COLANG_INPUT"]}, 1, 0]}},
                                "under_1ms": {"$sum": {"$cond": [{"$lt": ["$latency_ms", FAST_PATH_MS]}, 1, 0]}},
                                "over_100ms": {"$sum": {"$cond": [{"$gt": ["$latency_ms", COLANG_BUDGET_MS]}, 1, 0]}},
                                "avg_latency": {"$avg": "$latency_ms"},
                            }
                        }
                    ],
                    "threats": [
                        {"$match": {"threat_category": {"$ne": None}}},
                        {"$group": {"_id": "$threat_category", "count": {"$sum": 1}}},
                    ],
                }
            }
        ]
        result = await self._db[AUDIT_LOGS].aggregate(pipeline).to_list(length=1)
        facets = result[0] if result else {"totals": [], "threats": []}
        if not facets["totals"]:
            return _empty_summary()
        t = facets["totals"][0]
        total = t["total"]
        p50, p99 = await self._latency_percentiles(total)
        return {
            "total_requests": total,
            "blocked_requests": t["blocked"],
            "altered_requests": t["altered"],
            "clean_requests": t["clean"],
            "block_rate_pct": round(t["blocked"] / total * 100, 2),
            "avg_latency_ms": round(t["avg_latency"] or 0.0, 2),
            "threat_distribution": {d["_id"]: d["count"] for d in facets["threats"]},
            "fast_path_blocks": t["fast_path"],
            "colang_blocks": t["colang"],
            "sanitized_outputs": t["altered"],
            "p50_latency_ms": p50,
            "p99_latency_ms": p99,
            "latency_zones": {
                "under_1ms": t["under_1ms"],
                "1_to_100ms": total - t["under_1ms"] - t["over_100ms"],
                "over_100ms": t["over_100ms"],
            },
        }

    async def _latency_percentiles(self, total: int) -> tuple:
        """Nearest-rank p50/p99 via indexed sort + skip, without loading every record."""

        async def at_rank(pct: float) -> float:
            cursor = (
                self._db[AUDIT_LOGS]
                .find({}, {"_id": 0, "latency_ms": 1})
                .sort("latency_ms", 1)
                .skip(nearest_rank_index(total, pct))
                .limit(1)
            )
            docs = await cursor.to_list(length=1)
            return round(float(docs[0].get("latency_ms", 0.0)), 2) if docs else 0.0

        return await at_rank(50), await at_rank(99)

    async def insert_telemetry_snapshot(self, snapshot: Dict[str, Any]) -> None:
        await self.connect()
        if self._db is not None:
            try:
                await self._db[TELEMETRY_SNAPSHOTS].insert_one(dict(snapshot))
                return
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to write telemetry snapshot to MongoDB (%s).", exc)
        self._memory[TELEMETRY_SNAPSHOTS].append(dict(snapshot))


audit_store = AuditStore()


def get_audit_store() -> AuditStore:
    return audit_store
