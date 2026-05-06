"""
Webhook Instagram (Graph API) → klasifikasi IndoBERT (judi-detector) → hapus komentar jika judi.

Variabel lingkungan:
  WEBHOOK_VERIFY_TOKEN    — sama dengan Verify Token di Meta Developer (GET challenge).
  META_APP_SECRET         — App Secret untuk validasi X-Hub-Signature-256 (disarankan produksi).
  IG_ACCESS_TOKEN         — token dengan izin instagram_manage_comments (Page/User long-lived).
  JUDI_DETECTOR_URL       — base URL servis IndoBERT, default http://127.0.0.1:5000
  GRAPH_HOST              — default graph.instagram.com
  GRAPH_API_VERSION       — default v21.0
  MIN_CONFIDENCE_JUDI     — opsional; jika di-set (0–100), hapus hanya jika prob_judi >= ini
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
from typing import Any

import requests
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
    force=True,
)
log = logging.getLogger("instagram-webhook")

app = Flask(__name__)

WEBHOOK_VERIFY_TOKEN = os.environ.get("WEBHOOK_VERIFY_TOKEN", "").strip()
META_APP_SECRET = os.environ.get("META_APP_SECRET", "").strip()
IG_ACCESS_TOKEN = os.environ.get("IG_ACCESS_TOKEN", "").strip()
JUDI_DETECTOR_URL = os.environ.get("JUDI_DETECTOR_URL", "http://127.0.0.1:5000").rstrip("/")
GRAPH_HOST = os.environ.get("GRAPH_HOST", "graph.instagram.com").strip()
GRAPH_API_VERSION = os.environ.get("GRAPH_API_VERSION", "v21.0").strip()
_min_conf = os.environ.get("MIN_CONFIDENCE_JUDI", "").strip()
MIN_CONFIDENCE_JUDI: float | None = float(_min_conf) if _min_conf else None

if not WEBHOOK_VERIFY_TOKEN:
    log.warning("WEBHOOK_VERIFY_TOKEN kosong — webhook GET verification akan gagal.")
if not META_APP_SECRET:
    log.warning(
        "META_APP_SECRET kosong — X-Hub-Signature-256 tidak divalidasi (tidak disarankan produksi)."
    )
if not IG_ACCESS_TOKEN:
    log.warning("IG_ACCESS_TOKEN kosong — penghapusan komentar akan gagal.")


def _verify_meta_signature(raw_body: bytes, header_val: str | None) -> bool:
    if not META_APP_SECRET:
        return True
    if not header_val or not header_val.startswith("sha256="):
        return False
    want = header_val[7:]
    digest = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(digest, want)


def _extract_comment_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if payload.get("object") != "instagram":
        return []
    out: list[dict[str, Any]] = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            field = change.get("field")
            if field not in ("comments", "live_comments"):
                continue
            val = change.get("value") or {}
            cid = val.get("id")
            text = (val.get("text") or "").strip()
            if not cid:
                continue
            out.append({"comment_id": str(cid), "text": text, "field": field})
    return out


def _classify_teks(teks: str) -> dict[str, Any] | None:
    try:
        r = requests.post(
            f"{JUDI_DETECTOR_URL}/api/prediksi",
            json={"teks": teks},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        log.exception("Gagal memanggil judi-detector: %s", e)
        return None


def _should_delete_as_judi(result: dict[str, Any]) -> bool:
    if result.get("label") != "judi":
        return False
    if MIN_CONFIDENCE_JUDI is None:
        return True
    try:
        prob = float(result.get("prob_judi", 0))
    except (TypeError, ValueError):
        return False
    return prob >= MIN_CONFIDENCE_JUDI


def _delete_instagram_comment(comment_id: str) -> bool:
    if not IG_ACCESS_TOKEN:
        return False
    url = f"https://{GRAPH_HOST}/{GRAPH_API_VERSION}/{comment_id}"
    try:
        r = requests.delete(
            url,
            params={"access_token": IG_ACCESS_TOKEN},
            timeout=30,
        )
        if r.status_code in (200, 204):
            try:
                data = r.json() if r.content else {}
            except ValueError:
                data = {}
            if not data or data.get("success") is True:
                log.info("Komentar %s dihapus (Graph API).", comment_id)
                return True
        log.warning(
            "Hapus komentar %s: HTTP %s body=%s",
            comment_id,
            r.status_code,
            r.text[:500],
        )
    except requests.RequestException as e:
        log.exception("Request hapus komentar gagal: %s", e)
    return False


@app.route("/webhooks/instagram", methods=["GET", "POST"])
def webhooks_instagram():
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        if mode == "subscribe" and token == WEBHOOK_VERIFY_TOKEN and challenge:
            log.info("Webhook subscription verified.")
            return challenge, 200, {"Content-Type": "text/plain"}
        log.warning("Verifikasi webhook ditolak (mode/token).")
        return "Forbidden", 403

    raw = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256")
    if not _verify_meta_signature(raw, sig):
        log.warning("Signature tidak valid atau tidak ada.")
        return "Invalid signature", 403

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log.warning("Body bukan JSON valid.")
        return "Bad Request", 400

    events = _extract_comment_events(payload)
    for ev in events:
        comment_id = ev["comment_id"]
        text = ev["text"]
        if not text:
            log.info("Lewati komentar %s (teks kosong).", comment_id)
            continue
        result = _classify_teks(text)
        if not result:
            continue
        log.info(
            "Komentar %s: label=%s prob_judi=%s",
            comment_id,
            result.get("label"),
            result.get("prob_judi"),
        )
        if _should_delete_as_judi(result):
            _delete_instagram_comment(comment_id)
        else:
            log.debug("Tidak judi atau di bawah ambang — komentar dibiarkan.")

    # Selalu 200 cepat agar Meta tidak spam retry untuk payload yang sudah diproses
    return "EVENT_RECEIVED", 200


@app.route("/health")
def health():
    return jsonify(
        status="ok",
        judi_detector_url=JUDI_DETECTOR_URL,
        graph=f"{GRAPH_HOST}/{GRAPH_API_VERSION}",
        signature_check=bool(META_APP_SECRET),
        min_confidence_judi=MIN_CONFIDENCE_JUDI,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "3000")), debug=False)
