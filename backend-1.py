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
 
 
