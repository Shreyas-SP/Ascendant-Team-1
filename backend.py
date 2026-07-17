"""
BACKEND
===================================================
Layer 1   : Account Federation / Asset Graph / Token Vault / Metadata Ingest
Layer 2   : Vital Records / Consensus / Dead-Man's Switch / Audit Ledger
Layer 3   : Financial Drain Sorter / Tier Router / State Machine / Execution
Layer 4   : Legacy Packet Compiler (Sentiment / Compression / Crypto Envelope)
Layers 5-7: Compliance Router / Court PDF / Billing / Multi-Tenant RBAC

Language: Python 3.11+
Deps    : cryptography (Fernet envelope encryption), fpdf2 (PDF generation),
          stdlib only otherwise (hashlib, gzip, json, statistics, dataclasses).

All variable names are lowercase to separate it from the frontend. 
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import statistics  # noqa: F401 — retained from L4 spec
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fpdf import FPDF
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# ======================================================================
# PATHS & CONFIG
# ======================================================================

_BASE_DIR = Path(__file__).resolve().parent
_OUTPUT_DIR = _BASE_DIR / "output"
_PACKET_DIR = _OUTPUT_DIR / "packets"
_REPORT_DIR = _OUTPUT_DIR / "reports"


class settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = f"sqlite:///{(_BASE_DIR / 'cognitive_probate.db').as_posix()}"
    vault_master_key: str = "dev-only-change-me-32bytes-min!!"
    cooling_off_days: int = 14
    consensus_threshold: float = 2.0
    api_host: str = "127.0.0.1"
    api_port: int = 8000


@lru_cache
def get_settings() -> settings:
    return settings()


__version__ = "1.0.0-merged-L1-L7"

# ======================================================================
# ENUMS — L1–L3 MERGE CONTRACT + L4–L7 EXTENSIONS
# ======================================================================

class assetcategory(str, Enum):
    subscription = "subscription"
    financial = "financial"
    cloud_storage = "cloud_storage"
    media = "media"
    correspondence = "correspondence"


class dispositionintent(str, Enum):
    archive = "archive"
    transfer = "transfer"
    cancel = "cancel"
    delete = "delete"


class executionstate(str, Enum):
    discovered = "discovered"
    pending_approval = "pending_approval"
    executing = "executing"
    completed = "completed"


class tierclassification(str, Enum):
    api_native = "api_native"
    browser_automation = "browser_automation"
    manual_packet = "manual_packet"


class assetdisposition(str, Enum):
    archive = "ARCHIVE"
    transfer = "TRANSFER_TO"
    delete = "DELETE"
    downgrade = "DOWNGRADE_TO_FREE"
    keep_active = "KEEP_ACTIVE"
    cancel = "CANCEL"


class role(str, Enum):
    decedent_owner = "DECEDENT_OWNER"
    executor = "EXECUTOR"
    beneficiary = "BENEFICIARY"
    tenant_admin = "TENANT_ADMIN"
    system_service = "SYSTEM_SERVICE"


_DISPOSITIONINTENT_TO_ASSETDISPOSITION: dict[str, assetdisposition] = {
    dispositionintent.archive.value: assetdisposition.archive,
    dispositionintent.transfer.value: assetdisposition.transfer,
    dispositionintent.cancel.value: assetdisposition.cancel,
    dispositionintent.delete.value: assetdisposition.delete,
}


# ======================================================================
# DATABASE — SQLALCHEMY (L1–L3 PERSISTENCE)
# ======================================================================

_settings = get_settings()
_connect_args = (
    {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(_settings.database_url, connect_args=_connect_args)
sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class base(DeclarativeBase):
    pass


class assetnode(base):
    """Layer 1 — Digital Asset Graph node."""

    __tablename__ = "layer1_assets"

    assetid: Mapped[str] = mapped_column(String(64), primary_key=True)
    providername: Mapped[str] = mapped_column(String(128), nullable=False)
    assetcategory: Mapped[str] = mapped_column(String(64), nullable=False)
    dispositionintent: Mapped[str] = mapped_column(String(64), nullable=False)
    beneficiaryid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    graphdependencies: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    financial_value_monthly: Mapped[float] = mapped_column(Float, default=0.0)
    encrypted_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class tokenvaultentry(base):
    """Layer 1 — OAuth / aggregator token vault."""

    __tablename__ = "layer1_token_vault"

    assetid: Mapped[str] = mapped_column(String(64), primary_key=True)
    providername: Mapped[str] = mapped_column(String(128), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class verificationrecord(base):
    """Layer 2 — verification + cooling-off state (one per estate/case)."""

    __tablename__ = "layer2_verification"

    case_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    consensusscore: Mapped[float] = mapped_column(Float, default=0.0)
    stateregistryhit: Mapped[bool] = mapped_column(Boolean, default=False)
    attestationcount: Mapped[int] = mapped_column(Integer, default=0)
    coolingoffstart: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    coolingoffend: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ledgerblockhash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    inactivity_days: Mapped[int] = mapped_column(Integer, default=0)
    dead_man_armed: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class auditledgerentry(base):
    """Layer 2 — cryptographic audit log."""

    __tablename__ = "layer2_audit_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    ledgerblockhash: Mapped[str] = mapped_column(String(128), nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class executionworkflow(base):
    """Layer 3 — per-asset execution workflow."""

    __tablename__ = "layer3_workflows"

    workflowid: Mapped[str] = mapped_column(String(64), primary_key=True)
    assetid: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    idempotencykey: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    executionstate: Mapped[str] = mapped_column(String(64), nullable=False)
    tierclassification: Mapped[str] = mapped_column(String(64), nullable=False)
    financialdrainrank: Mapped[int] = mapped_column(Integer, nullable=False)
    Humancheckpointtriggered: Mapped[bool] = mapped_column(Boolean, default=False)
    result_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def get_db() -> Generator[Session, None, None]:
    db = sessionlocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    base.metadata.create_all(bind=engine)


# ======================================================================
# PYDANTIC SCHEMAS — L1–L3 HTTP CONTRACT
# ======================================================================

class assetenrollrequest(BaseModel):
    assetid: str
    providername: str
    assetcategory: assetcategory
    dispositionintent: dispositionintent
    beneficiaryid: str | None = None
    graphdependencies: list[str] = Field(default_factory=list)
    financial_value_monthly: float = 0.0
    metadata: dict = Field(default_factory=dict)
    oauth_token: str | None = None


class assetnodeout(BaseModel):
    assetid: str
    providername: str
    assetcategory: str
    dispositionintent: str
    beneficiaryid: str | None
    graphdependencies: list[str]
    financial_value_monthly: float

    model_config = {"from_attributes": True}


class dependencyorderout(BaseModel):
    ordered_assetids: list[str]


class registryhitrequest(BaseModel):
    case_id: str
    deceased_name: str
    death_certificate_id: str


class attestationrequest(BaseModel):
    case_id: str
    contact_id: str


class deadmanconfigrequest(BaseModel):
    case_id: str
    armed: bool = False
    inactivity_days: int = 0


class verificationout(BaseModel):
    case_id: str
    consensusscore: float
    stateregistryhit: bool
    attestationcount: int
    coolingoffstart: datetime | None
    coolingoffend: datetime | None
    ledgerblockhash: str | None
    ready_for_execution: bool

    model_config = {"from_attributes": True}


class startexecutionrequest(BaseModel):
    case_id: str
    force_skip_cooling_off: bool = False


class approvecheckpointrequest(BaseModel):
    workflowid: str
    approved: bool = True


class workflowout(BaseModel):
    workflowid: str
    assetid: str
    case_id: str
    idempotencykey: str
    executionstate: executionstate | str
    tierclassification: tierclassification | str
    financialdrainrank: int
    Humancheckpointtriggered: bool
    result_note: str | None = None

    model_config = {"from_attributes": True}


# ======================================================================
# L4–L7 IN-MEMORY DATA MODELS
# ======================================================================

@dataclass
class digitalasset:
    """A single node in the user's Digital Asset Graph (L4+ runtime view)."""
    assetid: str
    userid: str
    provider: str
    category: str
    disposition: assetdisposition
    monthlycost: float = 0.0
    sentimentaltag: bool = False
    createdat: str = ""
    gpslat: float | None = None
    gpslon: float | None = None
    rawbytesize: int = 0
    content: bytes = b""
    beneficiaryid: str | None = None
    graphdependencies: list[str] = field(default_factory=list)


@dataclass
class fiduciarycontext:
    """Core identity + fiduciary-legal context threaded through every layer."""
    userid: str
    executorid: str
    dpoahash: str
    fiduciaryjurisdiction: str
    fiduciarybondstatus: str
    case_id: str = ""


@dataclass
class tenant:
    whitelabelid: str
    tenantname: str
    tenanttype: str


@dataclass
class principal:
    principalid: str
    principalrole: role
    whitelabelid: str


# ======================================================================
# SHARED CRYPTO HELPERS (L1 VAULT + L4 ENVELOPE)
# ======================================================================

def _vault_fernet() -> Fernet:
    key_material = get_settings().vault_master_key.encode("utf-8")
    digest = hashlib.sha256(key_material).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


# ======================================================================
# LAYER 1 — ENROLLMENT / GRAPH / VAULT / METADATA
# ======================================================================

def encrypt_metadata(metadata: dict) -> str:
    payload = json.dumps(metadata, sort_keys=True).encode("utf-8")
    return _vault_fernet().encrypt(payload).decode("utf-8")


def decrypt_metadata(ciphertext: str) -> dict:
    raw = _vault_fernet().decrypt(ciphertext.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


def store_token(db: Session, assetid: str, providername: str, oauth_token: str) -> tokenvaultentry:
    ciphertext = _vault_fernet().encrypt(oauth_token.encode("utf-8")).decode("utf-8")
    entry = db.get(tokenvaultentry, assetid)
    if entry is None:
        entry = tokenvaultentry(assetid=assetid, providername=providername, ciphertext=ciphertext)
        db.add(entry)
    else:
        entry.providername = providername
        entry.ciphertext = ciphertext
    db.commit()
    db.refresh(entry)
    return entry


def reveal_token(db: Session, assetid: str) -> str | None:
    entry = db.get(tokenvaultentry, assetid)
    if entry is None:
        return None
    return _vault_fernet().decrypt(entry.ciphertext.encode("utf-8")).decode("utf-8")


def enroll_asset(db: Session, req: assetenrollrequest) -> assetnodeout:
    if req.dispositionintent == dispositionintent.transfer and not req.beneficiaryid:
        raise HTTPException(status_code=400, detail="beneficiaryid required when dispositionintent=transfer")

    existing = db.get(assetnode, req.assetid)
    if existing:
        raise HTTPException(status_code=409, detail=f"assetid already exists: {req.assetid}")

    node = assetnode(
        assetid=req.assetid,
        providername=req.providername.lower(),
        assetcategory=req.assetcategory.value,
        dispositionintent=req.dispositionintent.value,
        beneficiaryid=req.beneficiaryid,
        graphdependencies=list(req.graphdependencies),
        financial_value_monthly=req.financial_value_monthly,
        encrypted_metadata=encrypt_metadata(req.metadata) if req.metadata else None,
    )
    db.add(node)

    if req.oauth_token:
        store_token(db, req.assetid, req.providername.lower(), req.oauth_token)

    db.commit()
    db.refresh(node)
    return assetnodeout.model_validate(node)


def list_assets(db: Session) -> list[assetnodeout]:
    rows = db.query(assetnode).all()
    return [assetnodeout.model_validate(r) for r in rows]


def get_asset(db: Session, assetid: str) -> assetnodeout:
    node = db.get(assetnode, assetid)
    if not node:
        raise HTTPException(status_code=404, detail="assetid not found")
    return assetnodeout.model_validate(node)


def resolve_execution_order(db: Session, assetids: list[str] | None = None) -> list[str]:
    q = db.query(assetnode)
    if assetids:
        q = q.filter(assetnode.assetid.in_(assetids))
    nodes = q.all()
    ids = {n.assetid for n in nodes}
    graph: dict[str, list[str]] = defaultdict(list)
    indegree: dict[str, int] = {i: 0 for i in ids}

    for node in nodes:
        for dep in node.graphdependencies or []:
            if dep not in ids:
                continue
            graph[dep].append(node.assetid)
            indegree[node.assetid] += 1

    queue = deque([i for i, d in indegree.items() if d == 0])
    ordered: list[str] = []
    while queue:
        cur = queue.popleft()
        ordered.append(cur)
        for nxt in graph[cur]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)

    if len(ordered) != len(ids):
        raise HTTPException(status_code=400, detail="Cycle detected in graphdependencies")
    return ordered


# ======================================================================
# LAYER 2 — VITAL RECORDS / CONSENSUS / DEAD-MAN / AUDIT LEDGER
# ======================================================================

def _hash_block(prev_hash: str | None, event_type: str, payload: dict, created_at: datetime) -> str:
    material = {
        "prev_hash": prev_hash or "GENESIS",
        "event_type": event_type,
        "payload": payload,
        "created_at": created_at.isoformat(),
    }
    raw = json.dumps(material, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def append_ledger(db: Session, case_id: str, event_type: str, payload: dict) -> str:
    last = (
        db.query(auditledgerentry)
        .filter(auditledgerentry.case_id == case_id)
        .order_by(auditledgerentry.id.desc())
        .first()
    )
    prev_hash = last.ledgerblockhash if last else None
    created_at = datetime.utcnow()
    ledgerblockhash = _hash_block(prev_hash, event_type, payload, created_at)
    entry = auditledgerentry(
        case_id=case_id,
        event_type=event_type,
        payload_json=json.dumps(payload, sort_keys=True),
        ledgerblockhash=ledgerblockhash,
        prev_hash=prev_hash,
        created_at=created_at,
    )
    db.add(entry)
    db.commit()
    return ledgerblockhash


def query_state_registry(deceased_name: str, death_certificate_id: str) -> bool:
    _ = deceased_name
    return bool(death_certificate_id) and death_certificate_id.upper().startswith("DC-")


def ensure_case(db: Session, case_id: str) -> verificationrecord:
    row = db.get(verificationrecord, case_id)
    if row is None:
        row = verificationrecord(case_id=case_id)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def configure_dead_man(db: Session, case_id: str, armed: bool, inactivity_days: int) -> verificationrecord:
    row = ensure_case(db, case_id)
    row.dead_man_armed = armed
    row.inactivity_days = inactivity_days
    db.commit()
    db.refresh(row)
    append_ledger(
        db,
        case_id,
        "DEAD_MAN_CONFIG",
        {"armed": armed, "inactivity_days": inactivity_days},
    )
    return row


def evaluate_inactivity(db: Session, case_id: str, threshold_days: int = 365) -> bool:
    row = ensure_case(db, case_id)
    if not row.dead_man_armed:
        return False
    if threshold_days <= 0:
        raise HTTPException(status_code=400, detail="threshold_days must be > 0")
    triggered = row.inactivity_days >= threshold_days
    if triggered:
        append_ledger(
            db,
            case_id,
            "DEAD_MAN_TRIGGERED",
            {"inactivity_days": row.inactivity_days, "threshold_days": threshold_days},
        )
    return triggered


def _verification_to_out(row: verificationrecord) -> verificationout:
    cfg = get_settings()
    ready = (
        row.consensusscore >= cfg.consensus_threshold
        and row.stateregistryhit
        and row.attestationcount >= 1
        and row.coolingoffend is not None
        and datetime.utcnow() >= row.coolingoffend
    )
    return verificationout(
        case_id=row.case_id,
        consensusscore=row.consensusscore,
        stateregistryhit=row.stateregistryhit,
        attestationcount=row.attestationcount,
        coolingoffstart=row.coolingoffstart,
        coolingoffend=row.coolingoffend,
        ledgerblockhash=row.ledgerblockhash,
        ready_for_execution=ready,
    )


def _recompute_consensus(db: Session, row: verificationrecord) -> verificationrecord:
    cfg = get_settings()
    dead_man = 0.5 if evaluate_inactivity(db, row.case_id) else 0.0
    row.consensusscore = (
        (1.0 if row.stateregistryhit else 0.0) + float(row.attestationcount) + dead_man
    )

    if (
        row.consensusscore >= cfg.consensus_threshold
        and row.stateregistryhit
        and row.attestationcount >= 1
        and row.coolingoffstart is None
    ):
        row.coolingoffstart = datetime.utcnow()
        row.coolingoffend = row.coolingoffstart + timedelta(days=cfg.cooling_off_days)
        row.ledgerblockhash = append_ledger(
            db,
            row.case_id,
            "COOLING_OFF_STARTED",
            {
                "consensusscore": row.consensusscore,
                "coolingoffstart": row.coolingoffstart.isoformat(),
                "coolingoffend": row.coolingoffend.isoformat(),
            },
        )
    else:
        row.ledgerblockhash = append_ledger(
            db,
            row.case_id,
            "CONSENSUS_UPDATED",
            {
                "consensusscore": row.consensusscore,
                "stateregistryhit": row.stateregistryhit,
                "attestationcount": row.attestationcount,
            },
        )

    db.commit()
    db.refresh(row)
    return row


def record_registry_hit(
    db: Session, case_id: str, deceased_name: str, death_certificate_id: str
) -> verificationout:
    hit = query_state_registry(deceased_name, death_certificate_id)
    row = ensure_case(db, case_id)
    row.stateregistryhit = hit
    db.commit()
    row = _recompute_consensus(db, row)
    return _verification_to_out(row)


def record_attestation(db: Session, case_id: str, contact_id: str) -> verificationout:
    row = ensure_case(db, case_id)
    row.attestationcount += 1
    db.commit()
    append_ledger(db, case_id, "ATTESTATION", {"contact_id": contact_id})
    row = _recompute_consensus(db, row)
    return _verification_to_out(row)


def get_verification(db: Session, case_id: str) -> verificationout:
    row = ensure_case(db, case_id)
    return _verification_to_out(row)


def assert_ready_for_execution(
    db: Session, case_id: str, force_skip_cooling_off: bool = False
) -> verificationrecord:
    row = ensure_case(db, case_id)
    cfg = get_settings()
    if row.consensusscore < cfg.consensus_threshold:
        raise HTTPException(status_code=409, detail="consensusscore below threshold")
    if not row.stateregistryhit or row.attestationcount < 1:
        raise HTTPException(
            status_code=409,
            detail="Need at least two independent confirmations (stateregistryhit + attestation)",
        )
    if not force_skip_cooling_off:
        if row.coolingoffend is None:
            raise HTTPException(status_code=409, detail="cooling-off not started")
        if datetime.utcnow() < row.coolingoffend:
            raise HTTPException(
                status_code=409,
                detail=f"cooling-off active until {row.coolingoffend.isoformat()}",
            )
    return row


# ======================================================================
# LAYER 3 — TIER ROUTING / DRAIN SORT / STATE MACHINE / EXECUTION
# ======================================================================

API_NATIVE_PROVIDERS = {"google", "microsoft", "dropbox", "apple"}
BROWSER_AUTOMATION_PROVIDERS = {"netflix", "spotify", "hulu", "gym", "planetfitness"}
CHECKPOINT_MONTHLY_THRESHOLD = 50.0

ALLOWED_TRANSITIONS: dict[executionstate, set[executionstate]] = {
    executionstate.discovered: {executionstate.pending_approval, executionstate.executing},
    executionstate.pending_approval: {executionstate.executing},
    executionstate.executing: {executionstate.completed},
    executionstate.completed: set(),
}


def classify_tier(providername: str) -> tierclassification:
    p = providername.lower()
    if p in API_NATIVE_PROVIDERS:
        return tierclassification.api_native
    if p in BROWSER_AUTOMATION_PROVIDERS:
        return tierclassification.browser_automation
    return tierclassification.manual_packet


def rank_assets_by_financial_drain(db: Session, ordered_assetids: list[str]) -> list[tuple[str, int]]:
    nodes = {
        n.assetid: n
        for n in db.query(assetnode).filter(assetnode.assetid.in_(ordered_assetids)).all()
    }
    dep_index = {aid: i for i, aid in enumerate(ordered_assetids)}

    def sort_key(assetid: str) -> tuple:
        node = nodes[assetid]
        intent = node.dispositionintent
        cancel_band = 0 if intent in (
            dispositionintent.cancel.value,
            dispositionintent.delete.value,
        ) else 1
        return (cancel_band, -float(node.financial_value_monthly or 0.0), dep_index[assetid])

    sorted_ids = sorted(ordered_assetids, key=sort_key)
    return [(aid, rank + 1) for rank, aid in enumerate(sorted_ids)]


def can_transition(current: str | executionstate, nxt: executionstate) -> bool:
    cur = executionstate(current) if isinstance(current, str) else current
    return nxt in ALLOWED_TRANSITIONS[cur]


def next_after_discover(Humancheckpointtriggered: bool) -> executionstate:
    if Humancheckpointtriggered:
        return executionstate.pending_approval
    return executionstate.executing


def run_browser_cancellation(providername: str, assetid: str) -> dict:
    return {
        "status": "REQUIRES_HUMAN_REVIEW",
        "providername": providername,
        "assetid": assetid,
        "sandbox": "playwright_isolation_stub",
        "note": "Install playwright browsers in prod; submission gated on Humancheckpointtriggered approval.",
    }


def _needs_checkpoint(node: assetnode, tier: tierclassification) -> bool:
    if tier != tierclassification.api_native:
        return True
    if (node.financial_value_monthly or 0) >= CHECKPOINT_MONTHLY_THRESHOLD:
        return True
    if node.dispositionintent == dispositionintent.transfer.value:
        return True
    return False


def _execute_action(db: Session, node: assetnode, tier: tierclassification) -> str:
    token_present = reveal_token(db, node.assetid) is not None
    if tier == tierclassification.api_native:
        return (
            f"API_NATIVE:{node.dispositionintent} on {node.providername} "
            f"(token={'yes' if token_present else 'no'})"
        )
    if tier == tierclassification.browser_automation:
        packet = run_browser_cancellation(node.providername, node.assetid)
        return f"BROWSER_AUTOMATION:{packet['status']}"
    return (
        f"MANUAL_PACKET: prefilled cancellation/export for {node.providername} "
        f"intent={node.dispositionintent} beneficiaryid={node.beneficiaryid}"
    )


def start_case_execution(
    db: Session, case_id: str, force_skip_cooling_off: bool = False
) -> list[workflowout]:
    assert_ready_for_execution(db, case_id, force_skip_cooling_off=force_skip_cooling_off)

    ordered = resolve_execution_order(db)
    if not ordered:
        raise HTTPException(status_code=400, detail="No Layer 1 assets enrolled")

    ranked = rank_assets_by_financial_drain(db, ordered)
    workflows: list[workflowout] = []

    for assetid, financialdrainrank in ranked:
        node = db.get(assetnode, assetid)
        assert node is not None
        tier = classify_tier(node.providername)
        Humancheckpointtriggered = _needs_checkpoint(node, tier)
        idempotencykey = f"{case_id}:{assetid}:v1"

        existing = db.query(executionworkflow).filter_by(idempotencykey=idempotencykey).first()
        if existing:
            workflows.append(workflowout.model_validate(existing))
            continue

        workflowid = f"wf_{uuid.uuid4().hex[:12]}"
        state = next_after_discover(Humancheckpointtriggered)
        wf = executionworkflow(
            workflowid=workflowid,
            assetid=assetid,
            case_id=case_id,
            idempotencykey=idempotencykey,
            executionstate=executionstate.discovered.value,
            tierclassification=tier.value,
            financialdrainrank=financialdrainrank,
            Humancheckpointtriggered=Humancheckpointtriggered,
        )
        db.add(wf)
        db.commit()
        db.refresh(wf)

        if can_transition(wf.executionstate, state):
            wf.executionstate = state.value
            wf.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(wf)

        append_ledger(
            db,
            case_id,
            "WORKFLOW_CREATED",
            {
                "workflowid": workflowid,
                "assetid": assetid,
                "financialdrainrank": financialdrainrank,
                "tierclassification": tier.value,
                "Humancheckpointtriggered": Humancheckpointtriggered,
                "executionstate": wf.executionstate,
            },
        )
        workflows.append(workflowout.model_validate(wf))

    append_ledger(db, case_id, "EXECUTION_BATCH_STARTED", {"workflow_count": len(workflows)})
    return workflows


def approve_checkpoint(db: Session, workflowid: str, approved: bool = True) -> workflowout:
    wf = db.get(executionworkflow, workflowid)
    if not wf:
        raise HTTPException(status_code=404, detail="workflowid not found")
    if wf.executionstate != executionstate.pending_approval.value:
        raise HTTPException(status_code=409, detail="workflow not awaiting approval")
    if not approved:
        wf.result_note = "Rejected at human checkpoint"
        db.commit()
        return workflowout.model_validate(wf)
    if not can_transition(wf.executionstate, executionstate.executing):
        raise HTTPException(status_code=409, detail="invalid state transition")
    wf.executionstate = executionstate.executing.value
    wf.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(wf)
    append_ledger(
        db,
        wf.case_id,
        "CHECKPOINT_APPROVED",
        {"workflowid": workflowid, "assetid": wf.assetid},
    )
    return workflowout.model_validate(wf)


def advance_executing(db: Session, workflowid: str) -> workflowout:
    wf = db.get(executionworkflow, workflowid)
    if not wf:
        raise HTTPException(status_code=404, detail="workflowid not found")
    if wf.executionstate != executionstate.executing.value:
        raise HTTPException(status_code=409, detail="workflow not in executing state")

    node = db.get(assetnode, wf.assetid)
    if not node:
        raise HTTPException(status_code=404, detail="assetid missing")

    note = _execute_action(db, node, tierclassification(wf.tierclassification))
    if not can_transition(wf.executionstate, executionstate.completed):
        raise HTTPException(status_code=409, detail="invalid state transition")
    wf.executionstate = executionstate.completed.value
    wf.result_note = note
    wf.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(wf)
    append_ledger(
        db,
        wf.case_id,
        "WORKFLOW_COMPLETED",
        {
            "workflowid": workflowid,
            "assetid": wf.assetid,
            "tierclassification": wf.tierclassification,
            "result_note": note,
        },
    )
    return workflowout.model_validate(wf)


def list_workflows(db: Session, case_id: str | None = None) -> list[workflowout]:
    q = db.query(executionworkflow)
    if case_id:
        q = q.filter(executionworkflow.case_id == case_id)
    rows = q.order_by(executionworkflow.financialdrainrank.asc()).all()
    return [workflowout.model_validate(r) for r in rows]


def run_all_workflows_to_completion(db: Session, case_id: str) -> list[workflowout]:
    """Advance every workflow through checkpoints to completed state."""
    completed: list[workflowout] = []
    for wf in list_workflows(db, case_id):
        if wf.executionstate == executionstate.pending_approval.value:
            wf = approve_checkpoint(db, wf.workflowid, approved=True)
        if wf.executionstate == executionstate.executing.value:
            wf = advance_executing(db, wf.workflowid)
        completed.append(wf)
    return completed


# ======================================================================
# L1 → L4 BRIDGE — UNIFY ASSET REPRESENTATIONS
# ======================================================================

def layer1_node_to_digitalasset(node: assetnode, userid: str) -> digitalasset:
    meta: dict[str, Any] = {}
    if node.encrypted_metadata:
        try:
            meta = decrypt_metadata(node.encrypted_metadata)
        except Exception:
            meta = {}

    disposition = _DISPOSITIONINTENT_TO_ASSETDISPOSITION.get(
        node.dispositionintent,
        assetdisposition.keep_active,
    )

    return digitalasset(
        assetid=node.assetid,
        userid=userid,
        provider=node.providername,
        category=node.assetcategory,
        disposition=disposition,
        monthlycost=float(node.financial_value_monthly or 0.0),
        sentimentaltag=bool(meta.get("sentimentaltag", False)),
        createdat=str(meta.get("createdat", node.created_at.isoformat() if node.created_at else "")),
        gpslat=meta.get("gpslat"),
        gpslon=meta.get("gpslon"),
        rawbytesize=int(meta.get("rawbytesize", 0)),
        content=bytes(meta.get("content_stub", b"")) if meta.get("content_stub") else os.urandom(256) if meta.get("simulate_content") else b"",
        beneficiaryid=node.beneficiaryid,
        graphdependencies=list(node.graphdependencies or []),
    )


def layer1_graph_to_digitalassets(db: Session, userid: str) -> list[digitalasset]:
    nodes = db.query(assetnode).all()
    return [layer1_node_to_digitalasset(n, userid) for n in nodes]
 
# ======================================================================
# LAYER 4.1 — SENTIMENT ANALYSIS CLASSIFIER (EXIF / CLUSTERING WORKER)
# ======================================================================
 
class sentimentclusterworker:
    """
    Groups sentimentally-tagged assets (photos, letters, voice notes) into
    coherent 'memory clusters' using timestamp proximity and, when present,
    GPS proximity from EXIF-equivalent metadata. This never auto-deletes —
    it only proposes groupings for human executor review before archival.
    """
 
    def __init__(self, time_window_hours: int = 72, gps_window_km: float = 25.0):
        self.time_window_hours = time_window_hours
        self.gps_window_km = gps_window_km
 
    @staticmethod
    def _haversine_km(lat1, lon1, lat2, lon2) -> float:
        import math
        r = 6371.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        return 2 * r * math.asin(min(1.0, a ** 0.5))
 
    def cluster(self, assets: list[digitalasset]) -> list[dict[str, Any]]:
        candidates = sorted(
            [a for a in assets if a.sentimentaltag and a.createdat],
            key=lambda a: a.createdat,
        )
        sentimentclusters: list[dict[str, Any]] = []
        current_cluster: list[digitalasset] = []
 
        def flush():
            if current_cluster:
                total_bytes = sum(a.rawbytesize for a in current_cluster)
                sentimentclusters.append({
                    "clusterid": str(uuid.uuid4()),
                    "assetids": [a.assetid for a in current_cluster],
                    "windowstart": current_cluster[0].createdat,
                    "windowend": current_cluster[-1].createdat,
                    "assetcount": len(current_cluster),
                    "clusterbytesize": total_bytes,
                })
 
        for asset in candidates:
            if not current_cluster:
                current_cluster.append(asset)
                continue
            prev = current_cluster[-1]
            prev_time = datetime.fromisoformat(prev.createdat)
            cur_time = datetime.fromisoformat(asset.createdat)
            time_ok = (cur_time - prev_time) <= timedelta(hours=self.time_window_hours)
 
            gps_ok = True
            if prev.gpslat is not None and asset.gpslat is not None:
                dist = self._haversine_km(prev.gpslat, prev.gpslon, asset.gpslat, asset.gpslon)
                gps_ok = dist <= self.gps_window_km
 
            if time_ok and gps_ok:
                current_cluster.append(asset)
            else:
                flush()
                current_cluster = [asset]
        flush()
        return sentimentclusters
 
 
# ======================================================================
# LAYER 4.2 — ARCHIVAL DATA COMPRESSION PIPELINE
# ======================================================================
 
class archivalcompressionpipeline:
    """
    Deterministically serializes and compresses the archived/transferred
    subset of the estate into a single binary blob prior to encryption.
    """
 
    @staticmethod
    def build_manifest(assets: list[digitalasset], clusters: list[dict[str, Any]]) -> dict[str, Any]:
        archivable = [
            a for a in assets
            if a.disposition in (assetdisposition.archive, assetdisposition.transfer)
        ]
        manifest = {
            "generatedat": datetime.now(timezone.utc).isoformat(),
            "assetcount": len(archivable),
            "assets": [
                {
                    "assetid": a.assetid,
                    "provider": a.provider,
                    "category": a.category,
                    "disposition": a.disposition.value,
                    "rawbytesize": a.rawbytesize,
                    "contenthash": hashlib.sha256(a.content).hexdigest(),
                }
                for a in archivable
            ],
            "sentimentclusters": clusters,
        }
        return manifest
 
    @staticmethod
    def compress(assets: list[digitalasset], manifest: dict[str, Any]) -> tuple[bytes, int]:
        archivable = [
            a for a in assets
            if a.disposition in (assetdisposition.archive, assetdisposition.transfer)
        ]
        raw_payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
        raw_payload += b"\x00CONTENT\x00" + b"".join(a.content for a in archivable)
        compressed = gzip.compress(raw_payload, compresslevel=9)
        payloadbytesize = len(compressed)
        return compressed, payloadbytesize
 
 
# ======================================================================
# LAYER 4.3 — CRYPTOGRAPHIC ENVELOPE PACKAGER
# ======================================================================
 
class cryptographicenvelopepackager:
    """
    Wraps the compressed archive in a symmetric encryption envelope
    (Fernet = AES-128-CBC + HMAC-SHA256, authenticated encryption).
    The envelope key is escrowed to the executor's key-share, never stored
    alongside the ciphertext.
    """
 
    def __init__(self, output_dir: str = "/home/claude/packets"):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir
 
    def package(self, compressed_payload: bytes, userid: str) -> dict[str, str]:
        envelopekey = Fernet.generate_key()
        fernet = Fernet(envelopekey)
        ciphertext = fernet.encrypt(compressed_payload)
 
        packetid = str(uuid.uuid4())
        filename = f"legacy_packet_{userid}_{packetid}.enc"
        packetoutputurl = os.path.join(self.output_dir, filename)
        with open(packetoutputurl, "wb") as f:
            f.write(ciphertext)
 
        return {
            "envelopekey": envelopekey.decode("utf-8"),
            "packetoutputurl": packetoutputurl,
            "ciphertextsize": str(len(ciphertext)),
        }
 
    @staticmethod
    def verify_decrypt(packetoutputurl: str, envelopekey: str) -> bytes:
        with open(packetoutputurl, "rb") as f:
            ciphertext = f.read()
        fernet = Fernet(envelopekey.encode("utf-8"))
        return fernet.decrypt(ciphertext)

# ======================================================================
# LAYER 5 — STATUTORY JURISDICTIONAL COMPLIANCE ROUTER
# ======================================================================
 
class jurisdictioncomplianceerror(Exception):
    pass
 
 
class statutoryjurisdictioncompliancerouter:
    """
    Routes an estate's execution plan through the correct legal ruleset
    based on fiduciaryjurisdiction. Blocks execution if bond status or
    jurisdictional prerequisites are not satisfied.
    """
 
    _ruleset_table: dict[str, dict[str, Any]] = {
        "US": {
            "statute": "RUFADAA",
            "requires_bond": True,
            "cooling_off_days": 21,
            "death_registry": "SSA_DMF / STATE_VITAL_RECORDS",
        },
        "EU": {
            "statute": "GDPR_ART17_ERASURE_BY_PROXY",
            "requires_bond": True,
            "cooling_off_days": 30,
            "death_registry": "NATIONAL_CIVIL_REGISTRY",
        },
        "IN": {
            "statute": "DPDP_ACT_2023_NOMINEE_RIGHTS",
            "requires_bond": True,
            "cooling_off_days": 30,
            "death_registry": "CRS_INDIA",
        },
        "UK": {
            "statute": "DIGITAL_ECONOMY_ACT",
            "requires_bond": True,
            "cooling_off_days": 21,
            "death_registry": "GRO_UK",
        },
    }
 
    def route(self, ctx: fiduciarycontext) -> dict[str, Any]:
        region = ctx.fiduciaryjurisdiction.split("-")[0].upper()
        ruleset = self._ruleset_table.get(region)
        if ruleset is None:
            raise jurisdictioncomplianceerror(
                f"no compliance ruleset registered for jurisdiction '{ctx.fiduciaryjurisdiction}'"
            )
        if ruleset["requires_bond"] and ctx.fiduciarybondstatus != "BONDED":
            raise jurisdictioncomplianceerror(
                f"executor {ctx.executorid} is not bonded "
                f"(status={ctx.fiduciarybondstatus}) — execution blocked under {ruleset['statute']}"
            )
        return {
            "jurisdiction": ctx.fiduciaryjurisdiction,
            "applicablestatute": ruleset["statute"],
            "coolingoffdays": ruleset["cooling_off_days"],
            "deathregistrysource": ruleset["death_registry"],
            "compliancecleared": True,
        }
 
 
# ======================================================================
# LAYER 6 — COURT-READY ACCOUNTING PDF BUILDER
# ======================================================================
 
class courtreadyaccountingpdfbuilder:
    """
    Generates a probate-court-admissible accounting document: itemized
    asset disposition, valuations, fees, and compliance attestation.
    Produces indexpdfhash (sha256 of the rendered PDF bytes) for the
    immutable audit log.
    """
 
    def __init__(self, output_dir: str = "/home/claude/reports"):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir
 
    def build(
        self,
        ctx: fiduciarycontext,
        assets: list[digitalasset],
        compliance: dict[str, Any],
        billing: dict[str, Any],
        packet_meta: dict[str, str],
    ) -> dict[str, str]:
        pdf = FPDF(format="A4")
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Cognitive Probate - Court-Ready Digital Estate Accounting", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).isoformat()}Z", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
 
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "I. Fiduciary Identification", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for label, value in [
            ("User ID (Decedent)", ctx.userid),
            ("Executor ID", ctx.executorid),
            ("DPoA Hash", ctx.dpoahash),
            ("Jurisdiction", ctx.fiduciaryjurisdiction),
            ("Bond Status", ctx.fiduciarybondstatus),
            ("Applicable Statute", compliance["applicablestatute"]),
            ("Cooling-Off Period (days)", str(compliance["coolingoffdays"])),
        ]:
            pdf.cell(0, 6, f"{label}: {value}", new_x="LMARGIN", new_y="NEXT")
 
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "II. Digital Asset Disposition Ledger", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 6, "Asset ID", border=1)
        pdf.cell(35, 6, "Provider", border=1)
        pdf.cell(35, 6, "Category", border=1)
        pdf.cell(35, 6, "Disposition", border=1)
        pdf.cell(30, 6, "Monthly Cost", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for a in assets:
            pdf.cell(45, 6, a.assetid[:18], border=1)
            pdf.cell(35, 6, a.provider, border=1)
            pdf.cell(35, 6, a.category, border=1)
            pdf.cell(35, 6, a.disposition.value, border=1)
            pdf.cell(30, 6, f"${a.monthlycost:,.2f}", border=1, new_x="LMARGIN", new_y="NEXT")
 
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "III. Valuation & Fee Accounting", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for label, value in [
            ("Total Estate Asset Valuation", f"${billing['assetvaluation']:,.2f}"),
            ("Execution Fee (calculated)", f"${billing['executionfeecalculated']:,.2f}"),
            ("Effective Fee Rate", f"{billing['feerate'] * 100:.2f}%"),
            ("Recurring Financial Drain Eliminated / mo", f"${billing['monthlydraineliminated']:,.2f}"),
            ("Billing Circuit Breaker Status", billing["circuitbreakerstatus"]),
        ]:
            pdf.cell(0, 6, f"{label}: {value}", new_x="LMARGIN", new_y="NEXT")
 
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "IV. Legacy Packet Attestation", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Packet Output URL: {packet_meta['packetoutputurl']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Ciphertext Size (bytes): {packet_meta['ciphertextsize']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, "Envelope Key: [ESCROWED TO EXECUTOR - NOT PRINTED]", new_x="LMARGIN", new_y="NEXT")
 
        filename = f"court_accounting_{ctx.userid}_{uuid.uuid4()}.pdf"
        out_path = os.path.join(self.output_dir, filename)
        pdf.output(out_path)
 
        with open(out_path, "rb") as f:
            pdf_bytes = f.read()
        indexpdfhash = hashlib.sha256(pdf_bytes).hexdigest()
 
        return {"pdfpath": out_path, "indexpdfhash": indexpdfhash}


# ======================================================================
# LAYER 7A — AUTOMATED BILLING & MICRO-TRANSACTION EXECUTION CORE
# ======================================================================

class circuitbreakertripped(Exception):
    pass


class automatedbillingcore:
    def __init__(self, fee_rate: float = 0.015, anomaly_threshold: float = 0.40):
        self.fee_rate = fee_rate
        self.anomaly_threshold = anomaly_threshold
        self.subscribestatus = "ACTIVE"
        self.circuitbreakerstatus = "CLOSED"
        self._last_valuation: float | None = None

    def compute_valuation(self, assets: list[digitalasset]) -> float:
        assetvaluation = sum(a.monthlycost * 12 for a in assets if a.disposition != assetdisposition.delete)
        return round(assetvaluation, 2)

    def _check_circuit_breaker(self, new_valuation: float) -> None:
        if self._last_valuation is not None and self._last_valuation > 0:
            delta = abs(new_valuation - self._last_valuation) / self._last_valuation
            if delta > self.anomaly_threshold:
                self.circuitbreakerstatus = "OPEN"
                raise circuitbreakertripped(
                    f"valuation delta {delta:.2%} exceeds anomaly threshold "
                    f"{self.anomaly_threshold:.2%} — billing halted for manual review"
                )
        self._last_valuation = new_valuation

    def execute_billing(self, ctx: fiduciarycontext, assets: list[digitalasset]) -> dict[str, Any]:
        if self.subscribestatus != "ACTIVE":
            raise circuitbreakertripped(
                f"userid {ctx.userid} subscribestatus={self.subscribestatus} — cannot bill"
            )

        assetvaluation = self.compute_valuation(assets)
        self._check_circuit_breaker(assetvaluation)

        executionfeecalculated = round(assetvaluation * self.fee_rate, 2)
        monthly_drain_eliminated = round(
            sum(
                a.monthlycost
                for a in assets
                if a.disposition in (assetdisposition.cancel, assetdisposition.delete)
            ),
            2,
        )

        transactionid = str(uuid.uuid4())
        return {
            "transactionid": transactionid,
            "userid": ctx.userid,
            "executorid": ctx.executorid,
            "assetvaluation": assetvaluation,
            "executionfeecalculated": executionfeecalculated,
            "feerate": self.fee_rate,
            "monthlydraineliminated": monthly_drain_eliminated,
            "billedagainst": "ESTATE_ACCOUNT",
            "status": "SETTLED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subscribestatus": self.subscribestatus,
            "circuitbreakerstatus": self.circuitbreakerstatus,
        }


# ======================================================================
# LAYER 7B — MULTI-TENANT RBAC SECURITY MODULE
# ======================================================================

class accessdeniederror(Exception):
    pass


_permission_matrix: dict[role, set[str]] = {
    role.decedent_owner: {"read_graph", "write_graph", "sign_dpoa"},
    role.executor: {"read_graph", "approve_action", "trigger_billing", "download_packet", "download_pdf"},
    role.beneficiary: {"read_own_transfers"},
    role.tenant_admin: {"read_graph", "read_billing", "manage_tenant_users"},
    role.system_service: {"read_graph", "write_graph", "execute_action", "trigger_billing", "write_audit_log"},
}


class multitenantrbacsecuritymodule:
    def __init__(self):
        self._audit_log: list[dict[str, Any]] = []

    def authorize(self, actor: principal, action: str, resource_whitelabelid: str) -> bool:
        entry = {
            "eventid": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principalid": actor.principalid,
            "role": actor.principalrole.value,
            "action": action,
            "resourcewhitelabelid": resource_whitelabelid,
            "actorwhitelabelid": actor.whitelabelid,
        }

        if actor.whitelabelid != resource_whitelabelid:
            entry["result"] = "DENIED_TENANT_ISOLATION"
            self._audit_log.append(entry)
            raise accessdeniederror(
                f"principal {actor.principalid} (tenant={actor.whitelabelid}) "
                f"denied cross-tenant access to resource tenant={resource_whitelabelid}"
            )

        allowed_actions = _permission_matrix.get(actor.principalrole, set())
        if action not in allowed_actions:
            entry["result"] = "DENIED_ROLE_PERMISSION"
            self._audit_log.append(entry)
            raise accessdeniederror(
                f"principal {actor.principalid} with role {actor.principalrole.value} "
                f"lacks permission for action '{action}'"
            )

        entry["result"] = "GRANTED"
        self._audit_log.append(entry)
        return True

    def get_audit_log(self) -> list[dict[str, Any]]:
        return self._audit_log


 # ======================================================================
# LAYER 4–7 ORCHESTRATOR (POST L3 EXECUTION)
# ======================================================================

class cognitiveprobateorchestrator:
    def __init__(self, whitelabelid: str = "TENANT_DIRECT_001"):
        self.whitelabelid = whitelabelid
        self.rbac = multitenantrbacsecuritymodule()
        self.compliance_router = statutoryjurisdictioncompliancerouter()
        self.billing_core = automatedbillingcore()
        self.pdf_builder = courtreadyaccountingpdfbuilder()
        self.packager = cryptographicenvelopepackager()
        self.cluster_worker = sentimentclusterworker()

    def run(
        self,
        ctx: fiduciarycontext,
        assets: list[digitalasset],
        layer2_ledgerblockhash: str | None = None,
        layer3_workflows: list[workflowout] | None = None,
    ) -> dict[str, Any]:
        system_actor = principal(
            principalid="orchestrator_svc",
            principalrole=role.system_service,
            whitelabelid=self.whitelabelid,
        )
        executor_actor = principal(
            principalid=ctx.executorid,
            principalrole=role.executor,
            whitelabelid=self.whitelabelid,
        )

        self.rbac.authorize(system_actor, "read_graph", self.whitelabelid)
        self.rbac.authorize(executor_actor, "approve_action", self.whitelabelid)

        compliance = self.compliance_router.route(ctx)
        sentimentclusters = self.cluster_worker.cluster(assets)
        manifest = archivalcompressionpipeline.build_manifest(assets, sentimentclusters)
        compressed_payload, payloadbytesize = archivalcompressionpipeline.compress(assets, manifest)

        self.rbac.authorize(executor_actor, "download_packet", self.whitelabelid)
        packet_meta = self.packager.package(compressed_payload, ctx.userid)

        self.rbac.authorize(executor_actor, "trigger_billing", self.whitelabelid)
        billing_record = self.billing_core.execute_billing(ctx, assets)

        self.rbac.authorize(executor_actor, "download_pdf", self.whitelabelid)
        pdf_meta = self.pdf_builder.build(
            ctx, assets, compliance, billing_record, packet_meta,
            layer2_ledgerblockhash=layer2_ledgerblockhash,
            layer3_workflows=layer3_workflows,
        )

        return {
            "userid": ctx.userid,
            "executorid": ctx.executorid,
            "case_id": ctx.case_id,
            "dpoahash": ctx.dpoahash,
            "fiduciaryjurisdiction": ctx.fiduciaryjurisdiction,
            "fiduciarybondstatus": ctx.fiduciarybondstatus,
            "compliance": compliance,
            "sentimentclusters": sentimentclusters,
            "payloadbytesize": payloadbytesize,
            "envelopekey": packet_meta["envelopekey"],
            "packetoutputurl": packet_meta["packetoutputurl"],
            "indexpdfhash": pdf_meta["indexpdfhash"],
            "pdfpath": pdf_meta["pdfpath"],
            "assetvaluation": billing_record["assetvaluation"],
            "executionfeecalculated": billing_record["executionfeecalculated"],
            "subscribestatus": self.billing_core.subscribestatus,
            "whitelabelid": self.whitelabelid,
            "circuitbreakerstatus": self.billing_core.circuitbreakerstatus,
            "rbacauditlog": self.rbac.get_audit_log(),
        }


# ======================================================================
# FULL PIPELINE ORCHESTRATOR — L1 → L2 → L3 → L4 → L5 → L6 → L7
# ======================================================================

class fullpipelineorchestrator:
    """
    Chronological merge entrypoint:
      L1 enroll → L2 verify → L3 execute → L4 packet → L5 compliance →
      L6 PDF → L7 billing/RBAC
    """

    def __init__(self, whitelabelid: str = "TENANT_DIRECT_001"):
        self.whitelabelid = whitelabelid
        self.l47 = cognitiveprobateorchestrator(whitelabelid=whitelabelid)

    def run(
        self,
        db: Session,
        ctx: fiduciarycontext,
        force_skip_cooling_off: bool = False,
        auto_complete_workflows: bool = True,
    ) -> dict[str, Any]:
        if not ctx.case_id:
            raise ValueError("fiduciarycontext.case_id is required for L2/L3 pipeline")

        verification = get_verification(db, ctx.case_id)
        if not verification.ready_for_execution and not force_skip_cooling_off:
            raise HTTPException(
                status_code=409,
                detail="Case not ready — complete L2 verification and cooling-off first",
            )

        layer3_workflows = start_case_execution(
            db, ctx.case_id, force_skip_cooling_off=force_skip_cooling_off
        )

        if auto_complete_workflows:
            layer3_workflows = run_all_workflows_to_completion(db, ctx.case_id)

        verification_row = ensure_case(db, ctx.case_id)
        digital_assets = layer1_graph_to_digitalassets(db, ctx.userid)

        l47_result = self.l47.run(
            ctx,
            digital_assets,
            layer2_ledgerblockhash=verification_row.ledgerblockhash,
            layer3_workflows=layer3_workflows,
        )

        return {
            "layer2_verification": verification.model_dump(),
            "layer3_workflows": [w.model_dump() for w in layer3_workflows],
            **l47_result,
        }


# ======================================================================
# FASTAPI — HTTP SURFACE (L1–L3 ROUTES + HEALTH)
# ======================================================================

layer1_router = APIRouter(prefix="/layer1", tags=["Layer1-Enrollment"])


@layer1_router.post("/assets", response_model=assetnodeout)
def post_asset(req: assetenrollrequest, db: Session = Depends(get_db)) -> assetnodeout:
    return enroll_asset(db, req)


@layer1_router.get("/assets", response_model=list[assetnodeout])
def get_assets(db: Session = Depends(get_db)) -> list[assetnodeout]:
    return list_assets(db)


@layer1_router.get("/assets/{assetid}", response_model=assetnodeout)
def get_one_asset(assetid: str, db: Session = Depends(get_db)) -> assetnodeout:
    return get_asset(db, assetid)


@layer1_router.get("/graph/order", response_model=dependencyorderout)
def get_graph_order(db: Session = Depends(get_db)) -> dependencyorderout:
    return dependencyorderout(ordered_assetids=resolve_execution_order(db))


layer2_router = APIRouter(prefix="/layer2", tags=["Layer2-Verification"])


@layer2_router.post("/registry-hit", response_model=verificationout)
def post_registry_hit(req: registryhitrequest, db: Session = Depends(get_db)) -> verificationout:
    return record_registry_hit(db, req.case_id, req.deceased_name, req.death_certificate_id)


@layer2_router.post("/attestation", response_model=verificationout)
def post_attestation(req: attestationrequest, db: Session = Depends(get_db)) -> verificationout:
    return record_attestation(db, req.case_id, req.contact_id)


@layer2_router.post("/dead-man", response_model=verificationout)
def post_dead_man(req: deadmanconfigrequest, db: Session = Depends(get_db)) -> verificationout:
    configure_dead_man(db, req.case_id, req.armed, req.inactivity_days)
    return get_verification(db, req.case_id)


@layer2_router.get("/verification/{case_id}", response_model=verificationout)
def get_case_verification(case_id: str, db: Session = Depends(get_db)) -> verificationout:
    return get_verification(db, case_id)


layer3_router = APIRouter(prefix="/layer3", tags=["Layer3-Execution"])


@layer3_router.post("/execute", response_model=list[workflowout])
def post_execute(req: startexecutionrequest, db: Session = Depends(get_db)) -> list[workflowout]:
    return start_case_execution(db, req.case_id, force_skip_cooling_off=req.force_skip_cooling_off)


@layer3_router.post("/checkpoint", response_model=workflowout)
def post_checkpoint(req: approvecheckpointrequest, db: Session = Depends(get_db)) -> workflowout:
    return approve_checkpoint(db, req.workflowid, req.approved)


@layer3_router.post("/advance/{workflowid}", response_model=workflowout)
def post_advance(workflowid: str, db: Session = Depends(get_db)) -> workflowout:
    return advance_executing(db, workflowid)


@layer3_router.get("/workflows", response_model=list[workflowout])
def get_workflows(case_id: str | None = None, db: Session = Depends(get_db)) -> list[workflowout]:
    return list_workflows(db, case_id)


app = FastAPI(
    title="Cognitive Probate — Unified Fiduciary Engine (L1–L7)",
    version=__version__,
    description="Merged backend: Layers 1–3 (enroll/verify/execute) + Layers 4–7 (packet/compliance/billing/RBAC).",
)


@app.on_event("startup")
def on_startup() -> None:
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    init_db()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "layers": ["layer1", "layer2", "layer3", "layer4", "layer5", "layer6", "layer7"],
        "version": __version__,
    }


app.include_router(layer1_router)
app.include_router(layer2_router)
app.include_router(layer3_router)


# ======================================================================
# DEMO / EXECUTION ENTRYPOINT — FULL L1→L7 SYNTHETIC ESTATE
# ======================================================================

def _seed_layer1_estate(db: Session, userid: str) -> None:
    """Enroll a synthetic estate into Layer 1 tables."""
    base_time = datetime(2026, 6, 1, 9, 0, 0)
    enrollments = [
        assetenrollrequest(
            assetid="acc_netflix_001", providername="netflix",
            assetcategory=assetcategory.subscription, dispositionintent=dispositionintent.cancel,
            financial_value_monthly=15.99,
        ),
        assetenrollrequest(
            assetid="acc_spotify_002", providername="spotify",
            assetcategory=assetcategory.subscription, dispositionintent=dispositionintent.cancel,
            financial_value_monthly=10.99,
        ),
        assetenrollrequest(
            assetid="acc_gdrive_003", providername="google",
            assetcategory=assetcategory.cloud_storage, dispositionintent=dispositionintent.archive,
            financial_value_monthly=1.99,
            metadata={
                "sentimentaltag": True,
                "createdat": (base_time + timedelta(hours=0)).isoformat(),
                "gpslat": 12.9716, "gpslon": 77.5946,
                "rawbytesize": 4_500_000, "simulate_content": True,
            },
            oauth_token="oauth_stub_google",
        ),
        assetenrollrequest(
            assetid="acc_photos_004", providername="google",
            assetcategory=assetcategory.media, dispositionintent=dispositionintent.transfer,
            beneficiaryid="ben_priya_001", financial_value_monthly=0.0,
            graphdependencies=["acc_gdrive_003"],
            metadata={
                "sentimentaltag": True,
                "createdat": (base_time + timedelta(hours=6)).isoformat(),
                "gpslat": 12.9720, "gpslon": 77.5950,
                "rawbytesize": 12_800_000, "simulate_content": True,
            },
        ),
        assetenrollrequest(
            assetid="acc_letters_005", providername="protonmail",
            assetcategory=assetcategory.correspondence, dispositionintent=dispositionintent.archive,
            financial_value_monthly=0.0,
            metadata={
                "sentimentaltag": True,
                "createdat": (base_time + timedelta(days=10)).isoformat(),
                "gpslat": 19.0760, "gpslon": 72.8777,
                "rawbytesize": 250_000, "simulate_content": True,
            },
        ),
        assetenrollrequest(
            assetid="acc_bank_006", providername="icici",
            assetcategory=assetcategory.financial, dispositionintent=dispositionintent.transfer,
            beneficiaryid="ben_priya_001", financial_value_monthly=0.0,
            graphdependencies=["acc_gdrive_003"],
        ),
    ]
    for req in enrollments:
        try:
            enroll_asset(db, req)
        except HTTPException as exc:
            if exc.status_code != 409:
                raise


def _build_fiduciary_context(userid: str, executorid: str, case_id: str) -> fiduciarycontext:
    dpoahash = hashlib.sha256(b"signed-dpoa-document-v1::" + userid.encode()).hexdigest()
    return fiduciarycontext(
        userid=userid,
        executorid=executorid,
        dpoahash=dpoahash,
        fiduciaryjurisdiction="US-CA",
        fiduciarybondstatus="BONDED",
        case_id=case_id,
    )


def _fast_forward_cooling_off(db: Session, case_id: str) -> None:
    row = ensure_case(db, case_id)
    if row.coolingoffend:
        row.coolingoffend = datetime.utcnow() - timedelta(seconds=1)
        db.commit()


if __name__ == "__main__":
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    init_db()

    userid = "usr_shreyas_9f21"
    executorid = "exe_priya_4a02"
    case_id = "case_shreyas_2026"

    db = sessionlocal()
    try:
        print("=" * 78)
        print("COGNITIVE PROBATE - UNIFIED L1->L7 PIPELINE EXECUTION")
        print("=" * 78)

        print("\n[LAYER 1] Enrolling digital asset graph...")
        _seed_layer1_estate(db, userid)
        ordered = resolve_execution_order(db)
        print(f"  enrolled assets: {len(list_assets(db))}")
        print(f"  dependency order: {ordered}")

        print("\n[LAYER 2] Verification & consensus...")
        record_registry_hit(db, case_id, "Shreyas Example", "DC-2026-0042")
        record_attestation(db, case_id, "contact_priya_001")
        _fast_forward_cooling_off(db, case_id)
        verification = get_verification(db, case_id)
        print(f"  consensusscore={verification.consensusscore}, ready={verification.ready_for_execution}")
        print(f"  ledgerblockhash={verification.ledgerblockhash}")

        ctx = _build_fiduciary_context(userid, executorid, case_id)
        pipeline = fullpipelineorchestrator(whitelabelid="TENANT_DIRECT_001")

        print("\n[LAYER 3->7] Running full pipeline (execute -> packet -> compliance -> PDF -> billing)...")
        result = pipeline.run(db, ctx, force_skip_cooling_off=True, auto_complete_workflows=True)

        print(json.dumps(
            {k: v for k, v in result.items() if k not in ("rbacauditlog", "layer3_workflows")},
            indent=2,
            default=str,
        ))

        print("\n" + "-" * 78)
        print("LAYER 3 WORKFLOWS")
        print("-" * 78)
        for wf in result["layer3_workflows"]:
            print(
                f"  {wf['workflowid']} | {wf['assetid']} | rank={wf['financialdrainrank']} | "
                f"{wf['tierclassification']} | {wf['executionstate']} | checkpoint={wf['Humancheckpointtriggered']}"
            )

        print("\n" + "-" * 78)
        print("RBAC AUDIT LOG (Layer 7B)")
        print("-" * 78)
        for entry in result["rbacauditlog"]:
            print(
                f"[{entry['result']:>24}] {entry['role']:<16} -> {entry['action']:<18} "
                f"(actor={entry['principalid']}, tenant={entry['actorwhitelabelid']})"
            )

        print("\n" + "-" * 78)
        print("VERIFICATION: decrypt legacy packet (Layer 4.3)")
        print("-" * 78)
        decrypted = cryptographicenvelopepackager.verify_decrypt(
            result["packetoutputurl"], result["envelopekey"]
        )
        decompressed = gzip.decompress(decrypted)
        manifest_json_end = decompressed.find(b"\x00CONTENT\x00")
        recovered_manifest = json.loads(decompressed[:manifest_json_end])
        print(f"decrypted + decompressed successfully: {len(decompressed)} bytes recovered")
        print(f"recovered manifest asset count: {recovered_manifest['assetcount']}")
        print(f"recovered sentiment cluster count: {len(recovered_manifest['sentimentclusters'])}")

        print("\n" + "-" * 78)
        print("VERIFICATION: RBAC cross-tenant denial (Layer 7B)")
        print("-" * 78)
        rogue_actor = principal(
            principalid="rogue_admin_999",
            principalrole=role.tenant_admin,
            whitelabelid="TENANT_OTHERFIRM_777",
        )
        try:
            pipeline.l47.rbac.authorize(rogue_actor, "read_billing", pipeline.whitelabelid)
        except accessdeniederror as e:
            print(f"CORRECTLY DENIED: {e}")

        print("\n" + "-" * 78)
        print("VERIFICATION: circuit breaker on anomalous re-valuation (Layer 7A)")
        print("-" * 78)
        inflated = layer1_graph_to_digitalassets(db, userid) + [
            digitalasset(
                assetid="acc_anomaly_999", userid=userid, provider="SuspiciousCorp",
                category="financial", disposition=assetdisposition.transfer,
                monthlycost=100000.0,
            )
        ]
        try:
            pipeline.l47.billing_core.execute_billing(ctx, inflated)
        except circuitbreakertripped as e:
            print(f"CORRECTLY TRIPPED: {e}")
            print(f"circuitbreakerstatus now = {pipeline.l47.billing_core.circuitbreakerstatus}")

        print("\n" + "=" * 78)
        print(f"Legacy packet written to : {result['packetoutputurl']}")
        print(f"Court-ready PDF written to: {result['pdfpath']}")
        print(f"indexpdfhash              : {result['indexpdfhash']}")
        print(f"L2 audit chain head       : {verification.ledgerblockhash}")
        print("=" * 78)
    finally:
        db.close()

 
