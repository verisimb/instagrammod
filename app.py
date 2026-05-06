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
  MONITOR_BASIC_USER / MONITOR_BASIC_PASSWORD — jika keduanya di-set → /monitor & /api/monitor/* pakai Basic Auth.
  MONITOR_DB_PATH — file SQLite (default `<folder app>/data/monitor.sqlite`).
  MONITOR_MAX_ROWS — batas baris dalam DB (default 2000).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from flask import Flask, Response, abort, jsonify, render_template_string, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
    force=True,
)
log = logging.getLogger("instagram-webhook")

app = Flask(__name__)

_APP_DIR = Path(__file__).resolve().parent

WEBHOOK_VERIFY_TOKEN = os.environ.get("WEBHOOK_VERIFY_TOKEN", "").strip()
META_APP_SECRET = os.environ.get("META_APP_SECRET", "").strip()
IG_ACCESS_TOKEN = os.environ.get("IG_ACCESS_TOKEN", "").strip()
JUDI_DETECTOR_URL = os.environ.get("JUDI_DETECTOR_URL", "http://127.0.0.1:5000").rstrip("/")
GRAPH_HOST = os.environ.get("GRAPH_HOST", "graph.instagram.com").strip()
GRAPH_API_VERSION = os.environ.get("GRAPH_API_VERSION", "v21.0").strip()
_min_conf = os.environ.get("MIN_CONFIDENCE_JUDI", "").strip()
MIN_CONFIDENCE_JUDI: float | None = float(_min_conf) if _min_conf else None

MONITOR_BASIC_USER = os.environ.get("MONITOR_BASIC_USER", "").strip()
MONITOR_BASIC_PASSWORD = os.environ.get("MONITOR_BASIC_PASSWORD", "").strip()
MONITOR_DB_PATH = os.environ.get(
    "MONITOR_DB_PATH",
    str(_APP_DIR / "data" / "monitor.sqlite"),
).strip()
MONITOR_MAX_ROWS = max(50, min(50_000, int(os.environ.get("MONITOR_MAX_ROWS", "2000"))))

if not WEBHOOK_VERIFY_TOKEN:
    log.warning("WEBHOOK_VERIFY_TOKEN kosong — webhook GET verification akan gagal.")
if not META_APP_SECRET:
    log.warning(
        "META_APP_SECRET kosong — X-Hub-Signature-256 tidak divalidasi (tidak disarankan produksi)."
    )
if not IG_ACCESS_TOKEN:
    log.warning("IG_ACCESS_TOKEN kosong — penghapusan komentar akan gagal.")

if not MONITOR_BASIC_USER or not MONITOR_BASIC_PASSWORD:
    log.warning(
        "MONITOR_BASIC_USER / MONITOR_BASIC_PASSWORD kosong — "
        "/monitor dapat diakses publik tanpa login (set untuk produksi)."
    )

_monitor_lock = threading.Lock()


def _db_connect() -> sqlite3.Connection:
    Path(MONITOR_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MONITOR_DB_PATH, timeout=30, check_same_thread=False)

    def dict_row(cur: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
        return {cur.description[i][0]: row[i] for i in range(len(row))}

    conn.row_factory = dict_row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _monitor_init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS moderation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            comment_id TEXT NOT NULL,
            text_preview TEXT,
            label TEXT,
            prob_judi REAL,
            action TEXT NOT NULL,
            detail TEXT
        )
        """
    )
    conn.commit()


with _monitor_lock:
    try:
        _mc = _db_connect()
        _monitor_init_schema(_mc)
        _mc.close()
    except Exception as e:
        log.warning("Monitoring DB tidak siap (%s); /monitor bisa error.", e)


def monitor_record(
    *,
    comment_id: str,
    text: str | None,
    label: str | None,
    prob_judi: float | None,
    action: str,
    detail: str | None = None,
) -> None:
    prev = text[:400] + ("…" if text and len(text) > 400 else "") if text else ""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        with _monitor_lock:
            conn = _db_connect()
            try:
                _monitor_init_schema(conn)
                conn.execute(
                    """
                    INSERT INTO moderation_events
                      (ts, comment_id, text_preview, label, prob_judi, action, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ts, comment_id, prev, label, prob_judi, action, detail),
                )
                conn.execute(
                    """
                    DELETE FROM moderation_events
                    WHERE id NOT IN (
                      SELECT id FROM moderation_events ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (MONITOR_MAX_ROWS,),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        log.warning("monitor_record gagal: %s", e)


def _monitor_auth_optional() -> None:
    """Jika credential di-set, wajib Basic Auth untuk /monitor & /api/monitor/*."""
    if not MONITOR_BASIC_USER or not MONITOR_BASIC_PASSWORD:
        return None
    auth = request.authorization
    if auth and auth.username == MONITOR_BASIC_USER and auth.password == MONITOR_BASIC_PASSWORD:
        return None
    return Response(
        "Unauthorized",
        401,
        {"WWW-Authenticate": 'Basic realm="Monitor"'},
        mimetype="text/plain",
    )


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


def _delete_instagram_comment(comment_id: str) -> tuple[bool, str]:
    if not IG_ACCESS_TOKEN:
        log.warning(
            "Skip hapus komentar %s: IG_ACCESS_TOKEN kosong di environment.",
            comment_id,
        )
        return False, "token kosong"
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
                return True, ""
        msg = f"HTTP {r.status_code}: {(r.text or '')[:300]}"
        log.warning(
            "Hapus komentar %s: HTTP %s body=%s",
            comment_id,
            r.status_code,
            r.text[:500],
        )
        return False, msg
    except requests.RequestException as e:
        log.exception("Request hapus komentar gagal: %s", e)
        return False, str(e)[:300]


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
        field = ev.get("field") or ""
        if not text:
            log.info("Lewati komentar %s (teks kosong).", comment_id)
            monitor_record(
                comment_id=comment_id,
                text=None,
                label=None,
                prob_judi=None,
                action="skipped",
                detail="teks kosong" + (f", field={field}" if field else ""),
            )
            continue
        result = _classify_teks(text)
        if not result:
            monitor_record(
                comment_id=comment_id,
                text=text,
                label=None,
                prob_judi=None,
                action="classifier_error",
                detail=f"judi-detector error / timeout ({JUDI_DETECTOR_URL})",
            )
            continue
        log.info(
            "Komentar %s: label=%s prob_judi=%s",
            comment_id,
            result.get("label"),
            result.get("prob_judi"),
        )
        label_s = result.get("label")
        prob = result.get("prob_judi")
        try:
            prob_f = float(prob) if prob is not None else None
        except (TypeError, ValueError):
            prob_f = None
        if _should_delete_as_judi(result):
            ok, detail = _delete_instagram_comment(comment_id)
            monitor_record(
                comment_id=comment_id,
                text=text,
                label=str(label_s) if label_s is not None else None,
                prob_judi=prob_f,
                action="deleted" if ok else "delete_failed",
                detail=None if ok or not detail else detail,
            )
        else:
            log.debug("Tidak judi atau di bawah ambang — komentar dibiarkan.")
            monitor_record(
                comment_id=comment_id,
                text=text,
                label=str(label_s) if label_s is not None else None,
                prob_judi=prob_f,
                action="kept",
                detail=(
                    None
                    if MIN_CONFIDENCE_JUDI is None or label_s != "judi"
                    else f"prob_judi < {MIN_CONFIDENCE_JUDI}"
                ),
            )

    # Selalu 200 cepat agar Meta tidak spam retry untuk payload yang sudah diproses
    return "EVENT_RECEIVED", 200


_MONITOR_PAGE = """
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Monitor moderasi Instagram</title>
  <style>
    :root { --bg: #0f1419; --card: #1a2332; --text: #e7ecf3; --muted: #8b98a8; --ok: #3dd598; --del: #ff6b6b; --keep: #6bcbff; --skip: #c9b058; --err: #ff9f43; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5; padding: 1.25rem 1rem 3rem; }
    h1 { font-size: 1.35rem; font-weight: 600; margin: 0 0 0.35rem 0; }
    p.meta { margin: 0 0 1rem; color: var(--muted); font-size: 0.9rem; }
    .auth-warn { background: #3d2914; border: 1px solid #8b6914; color: #f5e6c8; padding: 0.6rem 0.85rem;
      border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px;
      overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,.35); font-size: 0.82rem; }
    th { text-align: left; padding: 0.65rem 0.55rem; background: #243044; font-weight: 600; white-space: nowrap; }
    td { padding: 0.55rem; border-top: 1px solid rgba(255,255,255,.06); vertical-align: top;
      word-break: break-word; max-width: 28rem; }
    .action-kept { color: var(--keep); font-weight: 600; }
    .action-deleted { color: var(--del); font-weight: 600; }
    .action-delete_failed { color: var(--err); font-weight: 600; }
    .action-skipped, .action-classifier_error { color: var(--skip); font-weight: 600; }
    .refresh { margin-top: 1rem; color: var(--muted); font-size: 0.85rem; }
    a.reload { color: var(--keep); }
  </style>
</head>
<body>
  <h1>Monitor moderasi komentar</h1>
  <p class="meta">{{ max_rows }} entri terakhir • DB: {{ db_path }}</p>
  {% if auth_open %}
  <div class="auth-warn"><strong>Peringatan:</strong> halaman ini terbuka tanpa Basic Auth. Set MONITOR_BASIC_USER dan MONITOR_BASIC_PASSWORD di Coolify.</div>
  {% endif %}
  <table>
    <thead><tr>
      <th>Waktu</th><th>Komentar ID</th><th>Teks</th><th>Label</th><th>% judi</th><th>Tindakan</th><th>Detail</th>
    </tr></thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td>{{ r.ts }}</td>
        <td><code>{{ r.comment_id }}</code></td>
        <td>{{ r.text_preview or "—" }}</td>
        <td>{{ r.label or "—" }}</td>
        <td>{% if r.prob_judi is not none %}{{ "%.2f"|format(r.prob_judi) }}{% else %}—{% endif %}</td>
        <td class="action-{{ r.action }}">{{ r.action }}</td>
        <td>{{ r.detail or "—" }}</td>
      </tr>
    {% endfor %}
    {% if not rows %}
      <tr><td colspan="7">Belum ada event.</td></tr>
    {% endif %}
    </tbody>
  </table>
  <p class="refresh">Auto-idea: bookmark halaman ini. <a class="reload" href="{{ request.path }}">Muat ulang</a>.</p>
</body>
</html>
"""


@app.route("/monitor")
def monitor_dashboard():
    ac = _monitor_auth_optional()
    if ac:
        return ac
    rows: list[Any] = []
    try:
        with _monitor_lock:
            conn = _db_connect()
            try:
                _monitor_init_schema(conn)
                cur = conn.execute(
                    """
                    SELECT ts, comment_id, text_preview, label, prob_judi, action, detail
                    FROM moderation_events ORDER BY id DESC LIMIT ?
                    """,
                    (MONITOR_MAX_ROWS,),
                )
                rows = cur.fetchall()
            finally:
                conn.close()
    except Exception as e:
        log.exception("Monitor read DB: %s", e)
        abort(500)
    auth_open = not (MONITOR_BASIC_USER and MONITOR_BASIC_PASSWORD)
    return render_template_string(
        _MONITOR_PAGE,
        rows=rows,
        auth_open=auth_open,
        max_rows=MONITOR_MAX_ROWS,
        db_path=MONITOR_DB_PATH,
    )


@app.route("/api/monitor/events")
def monitor_events_json():
    ac = _monitor_auth_optional()
    if ac:
        return ac
    limit_raw = request.args.get("limit", "200")
    try:
        limit_n = max(1, min(500, int(limit_raw)))
    except ValueError:
        limit_n = 200
    out: list[dict[str, Any]] = []
    try:
        with _monitor_lock:
            conn = _db_connect()
            try:
                _monitor_init_schema(conn)
                cur = conn.execute(
                    """
                    SELECT id, ts, comment_id, text_preview, label, prob_judi, action, detail
                    FROM moderation_events ORDER BY id DESC LIMIT ?
                    """,
                    (limit_n,),
                )
                for row in cur.fetchall():
                    out.append(row)
            finally:
                conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"events": out, "count": len(out)})


@app.route("/health")
def health():
    return jsonify(
        status="ok",
        judi_detector_url=JUDI_DETECTOR_URL,
        graph=f"{GRAPH_HOST}/{GRAPH_API_VERSION}",
        signature_check=bool(META_APP_SECRET),
        min_confidence_judi=MIN_CONFIDENCE_JUDI,
        monitor_dashboard="/monitor",
        monitor_events_api="/api/monitor/events",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5050")), debug=False)
