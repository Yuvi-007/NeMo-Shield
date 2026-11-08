"""Async MongoDB persistence for the NeMo-Shield audit ledger and telemetry.

Uses motor when a MongoDB server is reachable. If motor is missing, the server
cannot be reached, or NEMO_SHIELD_FORCE_MEMORY_DB=1 is set, it falls back to an
in-process dict store so the API (and tests) keep working without a live DB.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nemo_shield.database")

DEFAULT_MONGODB_URI = "mongodb://localhost:27017"
DB_NAME = "nemo_shield"
AUDIT_LOGS = "audit_logs"
TELEMETRY_SNAPSHOTS = "telemetry_snapshots"
SERVER_SELECTION_TIMEOUT_MS = 1500

try:
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError:  # pragma: no cover - motor is listed in requirements.txt
    AsyncIOMotorClient = None  # type: ignore[assignment]


def _empty_summary() -> Dict[str, Any]:
    return {
        "total_requests": 0,
        "blocked_requests": 0,
        "altered_requests": 0,
        "clean_requests": 0,
        "block_rate_pct": 0.0,
        "avg_latency_ms": 0.0,
        "threat_distribution": {},
    }


def summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute a telemetry summary from raw audit log records."""
    if not records:
        return _empty_summary()
    verdicts = Counter(r.get("verdict") for r in records)
    threats = Counter(r["threat_category"] for r in records if r.get("threat_category"))
    total = len(records)
    blocked = verdicts.get("INPUT_BLOCKED", 0)
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "altered_requests": verdicts.get("OUTPUT_ALTERED", 0),
        "clean_requests": verdicts.get("ALLOWED", 0),
        "block_rate_pct": round(blocked / total * 100, 2),
        "avg_latency_ms": round(sum(float(r.get("latency_ms", 0.0)) for r in records) / total, 2),
        "threat_distribution": dict(threats),
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
        if os.getenv("NEMO_SHIELD_FORCE_MEMORY_DB") == "1" or AsyncIOMotorClient is None:
            logger.info("Audit store using in-memory fallback.")
            return
        uri = os.getenv("MONGODB_URI", DEFAULT_MONGODB_URI)
        try:
            client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS)
            await client.admin.command("ping")
        except Exception as exc:  # noqa: BLE001 - any connection failure triggers fallback
            logger.warning("MongoDB unavailable (%s); using in-memory audit store.", exc)
            return
        self._client = client
        self._db = client[DB_NAME]
        await self._db[AUDIT_LOGS].create_index("timestamp")
        await self._db[AUDIT_LOGS].create_index("verdict")
        logger.info("Audit store connected to MongoDB database '%s'.", DB_NAME)

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
        return {
            "total_requests": total,
            "blocked_requests": t["blocked"],
            "altered_requests": t["altered"],
            "clean_requests": t["clean"],
            "block_rate_pct": round(t["blocked"] / total * 100, 2),
            "avg_latency_ms": round(t["avg_latency"] or 0.0, 2),
            "threat_distribution": {d["_id"]: d["count"] for d in facets["threats"]},
        }

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
