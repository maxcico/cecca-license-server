import os
import re
import secrets
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    edition: Mapped[str] = mapped_column(String(16), default="full")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_installations: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Installation(Base):
    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_code: Mapped[str] = mapped_column(String(128), index=True)
    installation_id: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[str] = mapped_column(String(64), default="zvanein")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ── Configurazione ────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL", "")
API_SECRET = os.getenv("LICENSE_API_SECRET", "")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# SMTP (opzionale): se assenti, l'invio email avviene via mailto: nel browser
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "") or SMTP_USER
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL mancante")
if not API_SECRET:
    raise RuntimeError("LICENSE_API_SECRET mancante")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD mancante")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
basic_security = HTTPBasic()

app = FastAPI(title="CECCA License Server", version="2.0.0")


# ── Schemi ────────────────────────────────────────────────────────────────────


class ValidateIn(BaseModel):
    code: str | None = Field(default=None, max_length=128)
    installation_id: str | None = Field(default=None, max_length=128)
    app_id: str = Field(default="zvanein", max_length=64)
    request_mode: str | None = Field(default=None, max_length=32)


class LicenseCreateIn(BaseModel):
    code: str = Field(min_length=3, max_length=128)
    edition: str = Field(default="full", max_length=16)
    max_installations: int = Field(default=1, ge=1, le=500)
    email: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)


# ── Auth ──────────────────────────────────────────────────────────────────────


def _auth(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization[7:].strip()
    if token != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _admin_auth(credentials: HTTPBasicCredentials = Depends(basic_security)) -> str:
    user_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    pass_ok = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return credentials.username


# ── Helper ────────────────────────────────────────────────────────────────────


def _is_expired(value: datetime | None) -> bool:
    if value is None:
        return False
    ref = value if value.tzinfo else value.replace(tzinfo=UTC)
    return ref < datetime.now(UTC)


def _generate_license_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = "".join(secrets.choice(chars) for _ in range(4))
    p2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"CECCA-{p1}-{p2}"


def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM)


def _send_license_email(to_email: str, code: str, edition: str) -> tuple[bool, str]:
    """Invia il codice via SMTP. Ritorna (ok, messaggio)."""
    if not _smtp_configured():
        return (False, "SMTP non configurato sul server (vedi env SMTP_HOST/USER/PASS/FROM).")

    msg = EmailMessage()
    msg["Subject"] = "La tua licenza CECCA"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    body = f"""Ciao,

ecco il tuo codice di licenza CECCA ({edition.upper()}):

    {code}

Per attivarla:
  1. Apri CECCA sul tuo PC.
  2. Vai in Impostazioni → Licenza.
  3. Clicca "Attiva licenza" e incolla il codice.

Conserva questa email: il codice è personale e legato alla tua installazione.

Buon lavoro!
"""
    msg.set_content(body)

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                if SMTP_USE_TLS:
                    s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
    except Exception as e:
        return (False, f"Errore invio: {type(e).__name__}: {e}")
    return (True, "Email inviata.")


def _build_mailto(to_email: str, code: str, edition: str) -> str:
    """Fallback: link mailto: che apre il client di posta dell'admin con bozza pronta."""
    subj = quote("La tua licenza CECCA")
    body = quote(
        f"Ciao,\n\necco il tuo codice di licenza CECCA ({edition.upper()}):\n\n"
        f"    {code}\n\n"
        "Per attivarla:\n"
        "  1. Apri CECCA sul tuo PC.\n"
        "  2. Vai in Impostazioni → Licenza.\n"
        "  3. Clicca 'Attiva licenza' e incolla il codice.\n\n"
        "Buon lavoro!\n"
    )
    return f"mailto:{quote(to_email)}?subject={subj}&body={body}"


# ── HTML Admin ────────────────────────────────────────────────────────────────


def _esc(s: str | None) -> str:
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_admin_html(db: Session, *, message: str = "", search_email: str = "") -> str:
    q = select(License).order_by(License.id.desc())
    if search_email:
        q = q.where(License.email.ilike(f"%{search_email}%"))
    licenses = db.scalars(q.limit(200)).all()
    installs = db.scalars(select(Installation).order_by(Installation.id.desc()).limit(100)).all()
    suggested_code = _generate_license_code()
    smtp_status = "configurato" if _smtp_configured() else "NON configurato (uso mailto:)"
    msg_html = f"<div class='msg'>{_esc(message)}</div>" if message else ""

    licenses_rows = "".join(
        (
            "<tr class='" + ("revoked" if l.revoked_at else ("inactive" if not l.active else "active")) + "'>"
            f"<td>{l.id}</td>"
            f"<td><code>{_esc(l.code)}</code></td>"
            f"<td>{_esc(l.edition)}</td>"
            f"<td>{'sì' if l.active else 'no'}</td>"
            f"<td>{_esc(l.email) or '-'}</td>"
            f"<td title='{_esc(l.notes)}'>{(_esc(l.notes)[:30] + '…') if l.notes and len(l.notes) > 30 else (_esc(l.notes) or '-')}</td>"
            f"<td>{l.max_installations}</td>"
            f"<td>{l.expires_at.strftime('%Y-%m-%d') if l.expires_at else '-'}</td>"
            f"<td>{l.revoked_at.strftime('%Y-%m-%d') if l.revoked_at else '-'}</td>"
            "<td class='actions'>"
            + (
                f"<form method='post' action='/admin/licenses/revoke' style='display:inline'>"
                f"<input type='hidden' name='code' value='{_esc(l.code)}'/>"
                f"<button class='btn-danger' onclick=\"return confirm('Revocare la licenza {_esc(l.code)}?')\">Revoca</button>"
                f"</form>"
                if (l.active and not l.revoked_at)
                else (
                    f"<form method='post' action='/admin/licenses/restore' style='display:inline'>"
                    f"<input type='hidden' name='code' value='{_esc(l.code)}'/>"
                    f"<button class='btn-secondary'>Riattiva</button>"
                    f"</form>"
                )
            )
            + (
                f"<form method='post' action='/admin/licenses/email' style='display:inline;margin-left:6px'>"
                f"<input type='hidden' name='code' value='{_esc(l.code)}'/>"
                f"<button class='btn-primary'>Invia mail</button>"
                f"</form>"
                if l.email
                else ""
            )
            + (
                f"<form method='post' action='/admin/installations/reset' style='display:inline;margin-left:6px' "
                "onsubmit=\"return confirm("
                "'Rimuovere tutte le installazioni collegate a questa licenza? I PC vanno ri-collegati da questo pannello.'"
                ");\">"
                f"<input type='hidden' name='license_code' value='{_esc(l.code)}'/>"
                f"<input type='hidden' name='app_id' value='zvanein'/>"
                f"<button type='submit' class='btn-secondary'>Reset inst.</button>"
                f"</form>"
            )
            + "</td>"
            "</tr>"
        )
        for l in licenses
    )

    install_rows = "".join(
        (
            "<tr>"
            f"<td>{i.id}</td>"
            f"<td><code>{_esc(i.license_code)}</code></td>"
            f"<td><code>{_esc(i.installation_id)}</code></td>"
            f"<td>{_esc(i.app_id)}</td>"
            f"<td>{i.last_seen_at}</td>"
            "<td class='actions'>"
            f"<form method='post' action='/admin/installations/unlink' style='display:inline' "
            "onsubmit=\"return confirm('Scollegare questa installazione dal codice licenza?');\">"
            f"<input type='hidden' name='installation_id' value='{_esc(i.installation_id)}'/>"
            f"<input type='hidden' name='app_id' value='{_esc(i.app_id)}'/>"
            f"<button type='submit' class='btn-danger'>Scollega</button>"
            f"</form>"
            "</td>"
            "</tr>"
        )
        for i in installs
    )

    return f"""
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <title>CECCA License Admin</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, Segoe UI, Roboto, Arial; margin: 0; background: #f1f5f9; color: #0f172a; }}
    header {{ background: #1d4ed8; color: white; padding: 18px 24px; }}
    header h1 {{ margin: 0; font-size: 20px; }}
    header .smtp {{ font-size: 12px; opacity: 0.9; }}
    main {{ max-width: 1280px; margin: 24px auto; padding: 0 16px; }}
    .box {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 12px; padding: 18px; margin: 16px 0; box-shadow: 0 1px 2px rgba(15,23,42,0.04); }}
    .box h3 {{ margin: 0 0 12px; font-size: 16px; color: #1e293b; }}
    input, select, textarea {{ padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; margin: 4px 6px 4px 0; }}
    input[type=text], input[type=email], textarea {{ width: 320px; max-width: 100%; }}
    textarea {{ min-height: 60px; vertical-align: top; }}
    button {{ padding: 8px 14px; border: 0; border-radius: 6px; cursor: pointer; font-weight: 600; }}
    .btn-primary  {{ background: #1d4ed8; color: white; }}
    .btn-primary:hover {{ background: #1e40af; }}
    .btn-secondary{{ background: #64748b; color: white; }}
    .btn-danger   {{ background: #dc2626; color: white; }}
    .btn-danger:hover {{ background: #b91c1c; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: middle; }}
    th {{ background: #eff6ff; }}
    tr.inactive td, tr.revoked td {{ background: #fef2f2; color: #94a3b8; }}
    tr.revoked td {{ text-decoration: line-through; }}
    code {{ font-family: 'Courier New', monospace; font-size: 12px; background: #f1f5f9; padding: 2px 5px; border-radius: 3px; }}
    .msg {{ background: #dbeafe; color: #1e3a8a; border-left: 4px solid #1d4ed8; padding: 10px 12px; border-radius: 6px; margin: 0 0 12px; font-weight: 500; }}
    .actions form {{ margin: 0; padding: 0; }}
    .row {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-start; }}
    .row > div {{ flex: 1; min-width: 240px; }}
    .hint {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
  </style>
</head>
<body>
  <header>
    <h1>CECCA License Admin</h1>
    <div class="smtp">SMTP {smtp_status} · {len(licenses)} licenze · {len(installs)} installazioni</div>
  </header>
  <main>
    {msg_html}

    <div class="box">
      <h3>Crea nuova licenza</h3>
      <form method="post" action="/admin/licenses/create">
        <div class="row">
          <div>
            <label>Codice</label><br>
            <input id="license_code" name="code" value="{suggested_code}" required />
            <button type="button" class="btn-secondary" onclick="regenCode()">Genera</button>
            <div class="hint">Formato suggerito: CECCA-XXXX-XXXX</div>
          </div>
          <div>
            <label>Edizione</label><br>
            <select name="edition">
              <option value="full">full</option>
              <option value="demo">demo</option>
            </select>
            <label style="margin-left:12px">Max installazioni</label>
            <input type="number" min="1" max="500" name="max_installations" value="1" style="width:80px" />
          </div>
        </div>
        <div class="row" style="margin-top:8px">
          <div>
            <label>Email cliente (per invio codice)</label><br>
            <input type="email" name="email" placeholder="cliente@ristorante.it" />
          </div>
          <div>
            <label>Note (cliente, ristorante, riferimento contratto...)</label><br>
            <textarea name="notes" placeholder="Trattoria da Mario - Roma"></textarea>
          </div>
        </div>
        <div style="margin-top:8px">
          <label>Scadenza (opzionale, formato YYYY-MM-DD)</label>
          <input type="text" name="expires_at" placeholder="2026-12-31" pattern="\\d{{4}}-\\d{{2}}-\\d{{2}}" style="width:180px" />
          <button type="submit" class="btn-primary">Crea licenza</button>
        </div>
      </form>
    </div>

    <div class="box">
      <h3>Cerca licenza per email</h3>
      <form method="get" action="/admin">
        <input type="text" name="email" value="{_esc(search_email)}" placeholder="parte di email..." />
        <button type="submit" class="btn-secondary">Cerca</button>
        <a href="/admin" style="margin-left:8px">Reset</a>
      </form>
    </div>

    <div class="box">
      <h3>Collega installazione (zero-input)</h3>
      <form method="post" action="/admin/installations/link">
        <input name="license_code" placeholder="Codice licenza" required />
        <input name="installation_id" placeholder="Installation ID macchina" required />
        <input name="app_id" placeholder="zvanein" value="zvanein" />
        <button type="submit" class="btn-primary">Collega</button>
      </form>
    </div>

    <div class="box">
      <h3>Licenze ({len(licenses)})</h3>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Codice</th>
            <th>Ed.</th>
            <th>Attiva</th>
            <th>Email</th>
            <th>Note</th>
            <th>Max</th>
            <th>Scade</th>
            <th>Revocata</th>
            <th>Azioni</th>
          </tr>
        </thead>
        <tbody>{licenses_rows}</tbody>
      </table>
    </div>

    <div class="box">
      <h3>Installazioni ({len(installs)})</h3>
      <p class="hint" style="margin:0 0 10px">Ogni riga: zero-input. <strong>Scollega</strong> toglie un solo PC; <strong>Reset inst.</strong> sulla licenza azzera tutte le coppie licenza↔PC.</p>
      <table>
        <thead>
          <tr><th>ID</th><th>License</th><th>Installation ID</th><th>App ID</th><th>Last Seen</th><th>Azioni</th></tr>
        </thead>
        <tbody>{install_rows}</tbody>
      </table>
    </div>
  </main>
  <script>
    function randChunk() {{
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let out = "";
      for (let i = 0; i < 4; i++) out += chars[Math.floor(Math.random() * chars.length)];
      return out;
    }}
    function regenCode() {{
      const el = document.getElementById("license_code");
      if (!el) return;
      el.value = `CECCA-${{randChunk()}}-${{randChunk()}}`;
    }}
  </script>
</body>
</html>
"""


# ── Endpoints API (Bearer protected) ──────────────────────────────────────────


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    # Migrazioni soft per chi aggiorna da v1 (campi nuovi)
    with engine.begin() as conn:
        for stmt in (
            "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS email VARCHAR(200)",
            "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS notes TEXT",
            "CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email)",
        ):
            try:
                conn.exec_driver_sql(stmt)
            except Exception:
                pass


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _normalize_code(raw: str) -> str:
    code_key = re.sub(r"\s+", "", raw.strip().upper())
    return re.sub(r"-+", "-", code_key).strip("-")


def _activate_code_for_installation(
    db: Session,
    *,
    code_key: str,
    installation_id: str,
    app_id: str,
) -> dict:
    """Valida codice e registra/aggiorna installazione (rispetta max_installations)."""
    lic = db.scalar(select(License).where(License.code == code_key))
    if not lic:
        lic = db.scalar(select(License).where(func.upper(License.code) == code_key))
    if not lic or not lic.active or lic.revoked_at is not None or _is_expired(lic.expires_at):
        return {"ok": False, "reason": "invalid_or_expired"}

    iid = installation_id.strip()
    aid = (app_id or "zvanein").strip() or "zvanein"
    if not iid:
        return {"ok": False, "reason": "installation_id_required"}

    existing = db.scalars(
        select(Installation).where(
            Installation.installation_id == iid,
            Installation.app_id == aid,
        )
    ).first()

    if existing:
        if existing.license_code == lic.code:
            existing.last_seen_at = datetime.now(UTC)
            db.commit()
            return {"ok": True, "edition": lic.edition}
        return {"ok": False, "reason": "installation_linked_other_license"}

    linked = db.scalars(
        select(Installation).where(
            Installation.license_code == lic.code,
            Installation.app_id == aid,
        )
    ).all()
    if len(linked) >= lic.max_installations:
        return {"ok": False, "reason": "max_installations_reached"}

    db.add(
        Installation(
            license_code=lic.code,
            installation_id=iid,
            app_id=aid,
            last_seen_at=datetime.now(UTC),
        )
    )
    db.commit()
    return {"ok": True, "edition": lic.edition}


@app.post("/api/validate", dependencies=[Depends(_auth)])
def validate_license(payload: ValidateIn) -> dict:
    with SessionLocal() as db:
        if payload.code:
            if not (payload.installation_id or "").strip():
                return {"ok": False, "reason": "installation_id_required"}
            return _activate_code_for_installation(
                db,
                code_key=_normalize_code(payload.code),
                installation_id=payload.installation_id or "",
                app_id=payload.app_id,
            )

        if payload.installation_id:
            existing = db.scalars(
                select(Installation).where(
                    Installation.installation_id == payload.installation_id,
                    Installation.app_id == payload.app_id,
                )
            ).first()
            if existing:
                lic = db.scalar(select(License).where(License.code == existing.license_code))
                if not lic or not lic.active or lic.revoked_at is not None or _is_expired(lic.expires_at):
                    return {"ok": False, "reason": "license_revoked_or_expired"}
                existing.last_seen_at = datetime.now(UTC)
                db.commit()
                return {"ok": True, "edition": lic.edition}
            return {"ok": False, "reason": "installation_not_linked"}

    return {"ok": False, "reason": "invalid_request"}


# ── Endpoints Admin (HTTP Basic) ──────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def root_redirect() -> HTMLResponse:
    return HTMLResponse(
        '<html><body style="font-family:sans-serif;padding:24px">'
        '<h2>CECCA License Server</h2>'
        '<p>Server attivo. Vai su <a href="/admin">/admin</a> per gestire le licenze.</p>'
        "</body></html>"
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_home(_: str = Depends(_admin_auth), message: str = "", email: str = "") -> str:
    with SessionLocal() as db:
        return _render_admin_html(db, message=message, search_email=email)


@app.post("/admin/licenses/create")
def admin_create_license(
    code: str = Form(...),
    edition: str = Form(default="full"),
    max_installations: int = Form(default=1),
    email: str = Form(default=""),
    notes: str = Form(default=""),
    expires_at: str = Form(default=""),
    _: str = Depends(_admin_auth),
):
    payload = LicenseCreateIn(
        code=code.strip().upper(),
        edition=edition.strip().lower(),
        max_installations=max_installations,
        email=email.strip() or None,
        notes=notes.strip() or None,
    )
    expires_dt: datetime | None = None
    if expires_at.strip():
        try:
            expires_dt = datetime.strptime(expires_at.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return RedirectResponse(url="/admin?message=Formato+scadenza+non+valido", status_code=303)

    with SessionLocal() as db:
        existing = db.scalar(select(License).where(License.code == payload.code))
        if existing:
            return RedirectResponse(url="/admin?message=Licenza+gia+esistente", status_code=303)
        lic = License(
            code=payload.code,
            edition="full" if payload.edition != "demo" else "demo",
            active=True,
            max_installations=payload.max_installations,
            email=payload.email,
            notes=payload.notes,
            expires_at=expires_dt,
        )
        db.add(lic)
        db.commit()

    msg = f"Licenza+{quote(payload.code)}+creata"
    return RedirectResponse(url=f"/admin?message={msg}", status_code=303)


@app.post("/admin/licenses/revoke")
def admin_revoke_license(
    code: str = Form(...),
    _: str = Depends(_admin_auth),
):
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == code.strip()))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        lic.active = False
        lic.revoked_at = datetime.now(UTC)
        db.commit()
    return RedirectResponse(url=f"/admin?message=Licenza+{quote(code)}+revocata", status_code=303)


@app.post("/admin/licenses/restore")
def admin_restore_license(
    code: str = Form(...),
    _: str = Depends(_admin_auth),
):
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == code.strip()))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        lic.active = True
        lic.revoked_at = None
        db.commit()
    return RedirectResponse(url=f"/admin?message=Licenza+{quote(code)}+riattivata", status_code=303)


@app.post("/admin/licenses/email", response_class=HTMLResponse)
def admin_email_license(
    code: str = Form(...),
    _: str = Depends(_admin_auth),
):
    """Invia il codice all'email associata. Se SMTP non è configurato, mostra
    un link mailto: che apre il client di posta dell'admin con bozza pronta."""
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == code.strip()))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        if not lic.email:
            return RedirectResponse(
                url=f"/admin?message=Aggiungi+un'email+alla+licenza+{quote(code)}",
                status_code=303,
            )
        target_email = lic.email
        target_code = lic.code
        target_edition = lic.edition

    if _smtp_configured():
        ok, msg = _send_license_email(target_email, target_code, target_edition)
        result = (f"Email+inviata+a+{quote(target_email)}" if ok else f"Errore+SMTP:+{quote(msg)}")
        return RedirectResponse(url=f"/admin?message={result}", status_code=303)

    # Fallback: pagina che redirige a mailto:
    mailto = _build_mailto(target_email, target_code, target_edition)
    return HTMLResponse(
        f"""<!doctype html><html><head><meta charset="utf-8"/>
<meta http-equiv="refresh" content="0; url={_esc(mailto)}"/>
<title>Apertura client di posta...</title>
</head>
<body style="font-family:sans-serif;padding:24px">
<p>SMTP non configurato. Apertura del client di posta...</p>
<p>Se non si apre automaticamente, <a href="{_esc(mailto)}">clicca qui</a>.</p>
<p><a href="/admin">← Torna al pannello</a></p>
</body></html>"""
    )


@app.post("/admin/installations/link")
def admin_link_installation(
    license_code: str = Form(...),
    installation_id: str = Form(...),
    app_id: str = Form(default="zvanein"),
    _: str = Depends(_admin_auth),
):
    lc = license_code.strip()
    iid = installation_id.strip()
    aid = app_id.strip() or "zvanein"
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == lc))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        linked = db.scalars(
            select(Installation).where(
                Installation.license_code == lc,
                Installation.app_id == aid,
            )
        ).all()
        already = db.scalars(
            select(Installation).where(
                Installation.installation_id == iid,
                Installation.app_id == aid,
            )
        ).first()
        if already:
            already.license_code = lc
            already.last_seen_at = datetime.now(UTC)
            db.commit()
            return RedirectResponse(url="/admin?message=Installazione+riallineata", status_code=303)
        if len(linked) >= lic.max_installations:
            return RedirectResponse(url="/admin?message=Limite+installazioni+raggiunto", status_code=303)
        db.add(Installation(license_code=lc, installation_id=iid, app_id=aid, last_seen_at=datetime.now(UTC)))
        db.commit()
    return RedirectResponse(url="/admin?message=Installazione+collegata", status_code=303)


@app.post("/admin/installations/unlink")
def admin_unlink_installation(
    installation_id: str = Form(...),
    app_id: str = Form(default="zvanein"),
    _: str = Depends(_admin_auth),
):
    iid = installation_id.strip()
    aid = app_id.strip() or "zvanein"
    with SessionLocal() as db:
        rows = db.scalars(
            select(Installation).where(
                Installation.installation_id == iid,
                Installation.app_id == aid,
            )
        ).all()
        if not rows:
            return RedirectResponse(url="/admin?message=Installazione+non+trovata", status_code=303)
        for r in rows:
            db.delete(r)
        db.commit()
    return RedirectResponse(url="/admin?message=Installazione+scollegata", status_code=303)


@app.post("/admin/installations/reset")
def admin_reset_installations_for_license(
    license_code: str = Form(...),
    app_id: str = Form(default="zvanein"),
    _: str = Depends(_admin_auth),
):
    lc = license_code.strip()
    aid = app_id.strip() or "zvanein"
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == lc))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        rows = db.scalars(
            select(Installation).where(
                Installation.license_code == lc,
                Installation.app_id == aid,
            )
        ).all()
        if not rows:
            return RedirectResponse(url="/admin?message=Nessuna+installazione+da+resettare", status_code=303)
        for r in rows:
            db.delete(r)
        db.commit()
    return RedirectResponse(url="/admin?message=Installazioni+licenza+resettate", status_code=303)
