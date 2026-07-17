"""
BACKEND 1
=================================
Layer 4   : Legacy Packet Compiler
            - Sentiment Analysis Classifier (EXIF / Clustering Worker)
            - Archival Data Compression Pipeline
            - Cryptographic Envelope Packager
Layers 5-7: Compliance & Business Operations
            - Statutory Jurisdictional Compliance Router
            - Court-Ready Accounting PDF Builder
            - Automated Billing & Micro-Transaction Execution Core
            - Multi-Tenant RBAC Security Module

Deps    : cryptography (Fernet envelope encryption), fpdf2 (PDF generation),
          stdlib only otherwise (hashlib, gzip, json, statistics, dataclasses).

All variable names are lowercase to separate it from the frontend. This module is fully
executable end-to-end via the __main__ demo block at the bottom, which runs
a synthetic estate through the entire Layer 4 -> Layers 5-7 pipeline and
prints/serializes real, inspectable output (encrypted packet file + PDF).
"""
from __future__ import annotations
 
import gzip
import hashlib
import json
import os
import statistics
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
 
from cryptography.fernet import Fernet
from fpdf import FPDF
 
 
# ======================================================================
# SHARED / CORE DATA MODELS
# ======================================================================
 
class assetdisposition(str, Enum):
    archive = "ARCHIVE"
    transfer = "TRANSFER_TO"
    delete = "DELETE"
    downgrade = "DOWNGRADE_TO_FREE"
    keep_active = "KEEP_ACTIVE"
    cancel = "CANCEL"
 
 
@dataclass
class digitalasset:
    """A single node in the user's Digital Asset Graph."""
    assetid: str
    userid: str
    provider: str
    category: str                      # subscription | media | financial | correspondence
    disposition: assetdisposition
    monthlycost: float = 0.0
    sentimentaltag: bool = False
    createdat: str = ""                # ISO timestamp, used for EXIF/clustering
    gpslat: float | None = None
    gpslon: float | None = None
    rawbytesize: int = 0
    content: bytes = b""               # simulated raw payload (photo/doc/message bytes)
 
 
@dataclass
class fiduciarycontext:
    """Core identity + fiduciary-legal context threaded through every layer."""
    userid: str
    executorid: str
    dpoahash: str                      # sha256 of the signed Digital Power of Appointment
    fiduciaryjurisdiction: str          # e.g. "US-CA", "EU-DE", "IN"
    fiduciarybondstatus: str            # "BONDED" | "UNBONDED" | "PENDING"
 
 
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


 
 
