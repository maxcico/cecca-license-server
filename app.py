import os
import secrets
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, func, select
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Installation(Base):
    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_code: Mapped[str] = mapped_column(String(128), index=True)
    installation_id: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[str] = mapped_column(String(64), default="zvanein")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


DATABASE_URL = os.getenv("DATABASE_URL", "")
API_SECRET = os.getenv("LICENSE_API_SECRET", "")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

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

app = FastAPI(title="CECCA License Server", version="1.0.0")


class ValidateIn(BaseModel):
    code: str | None = Field(default=None, max_length=128)
    installation_id: str | None = Field(default=None, max_length=128)
    app_id: str = Field(default="zvanein", max_length=64)
    request_mode: str | None = Field(default=None, max_length=32)


class LicenseCreateIn(BaseModel):
    code: str = Field(min_length=3, max_length=128)
    edition: str = Field(default="full", max_length=16)
    max_installations: int = Field(default=1, ge=1, le=500)


def _auth(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization[7:].strip()
    if token != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _is_expired(value: datetime | None) -> bool:
    if value is None:
        return False
    ref = value if value.tzinfo else value.replace(tzinfo=UTC)
    return ref < datetime.now(UTC)


def _admin_auth(credentials: HTTPBasicCredentials = Depends(basic_security)) -> str:
    user_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    pass_ok = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return credentials.username


def _generate_license_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = "".join(secrets.choice(chars) for _ in range(4))
    p2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"CECCA-{p1}-{p2}"


def _render_admin_html(db: Session, *, message: str = "") -> str:
    licenses = db.scalars(select(License).order_by(License.id.desc()).limit(100)).all()
    installs = db.scalars(select(Installation).order_by(Installation.id.desc()).limit(100)).all()
    suggested_code = _generate_license_code()
    msg = f"<p style='color:#2563eb;font-weight:600'>{message}</p>" if message else ""
    licenses_rows = "".join(
        (
            "<tr>"
            f"<td>{l.id}</td>"
            f"<td>{l.code}</td>"
            f"<td>{l.edition}</td>"
            f"<td>{'yes' if l.active else 'no'}</td>"
            f"<td>{l.max_installations}</td>"
            f"<td>{l.expires_at or '-'}</td>"
            "</tr>"
        )
        for l in licenses
    )
    install_rows = "".join(
        (
            "<tr>"
            f"<td>{i.id}</td>"
            f"<td>{i.license_code}</td>"
            f"<td>{i.installation_id}</td>"
            f"<td>{i.app_id}</td>"
            f"<td>{i.last_seen_at}</td>"
            "</tr>"
        )
        for i in installs
    )
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>CECCA License Admin</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
    h1 {{ margin-bottom: 8px; }}
    .box {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 16px; margin: 16px 0; }}
    input, select {{ padding: 8px; margin: 6px 6px 6px 0; }}
    button {{ padding: 8px 12px; background: #1d4ed8; color: #fff; border: 0; border-radius: 6px; cursor: pointer; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 8px; text-align: left; }}
    th {{ background: #eff6ff; }}
  </style>
</head>
<body>
  <h1>CECCA License Admin</h1>
  <p>Gestione licenze e installazioni (Railway).</p>
  {msg}
  <div class="box">
    <h3>Crea Licenza</h3>
    <form method="post" action="/admin/licenses/create">
      <input id="license_code" name="code" value="{suggested_code}" placeholder="FULL-CLIENTE-001" required />
      <button type="button" onclick="regenCode()">Genera codice</button>
      <select name="edition">
        <option value="full">full</option>
        <option value="demo">demo</option>
      </select>
      <input type="number" min="1" max="500" name="max_installations" value="1" />
      <button type="submit">Crea</button>
    </form>
  </div>

  <div class="box">
    <h3>Attiva/Disattiva Licenza</h3>
    <form method="post" action="/admin/licenses/toggle">
      <input name="code" placeholder="Codice licenza" required />
      <select name="active">
        <option value="true">attiva</option>
        <option value="false">disattiva</option>
      </select>
      <button type="submit">Aggiorna</button>
    </form>
  </div>

  <div class="box">
    <h3>Collega Installazione (zero input)</h3>
    <form method="post" action="/admin/installations/link">
      <input name="license_code" placeholder="Codice licenza" required />
      <input name="installation_id" placeholder="Installation ID macchina" required />
      <input name="app_id" placeholder="zvanein" value="zvanein" />
      <button type="submit">Collega</button>
    </form>
  </div>

  <div class="box">
    <h3>Scollega installazione</h3>
    <form method="post" action="/admin/installations/unlink">
      <input name="installation_id" placeholder="Installation ID macchina" required />
      <input name="app_id" placeholder="zvanein" value="zvanein" />
      <button type="submit">Scollega</button>
    </form>
  </div>

  <div class="box">
    <h3>Reset installazioni licenza</h3>
    <form method="post" action="/admin/installations/reset">
      <input name="license_code" placeholder="Codice licenza" required />
      <input name="app_id" placeholder="zvanein" value="zvanein" />
      <button type="submit">Reset</button>
    </form>
  </div>

  <div class="box">
    <h3>Licenze</h3>
    <table>
      <thead><tr><th>ID</th><th>Code</th><th>Edition</th><th>Active</th><th>Max</th><th>Expires</th></tr></thead>
      <tbody>{licenses_rows}</tbody>
    </table>
  </div>

  <div class="box">
    <h3>Installazioni</h3>
    <table>
      <thead><tr><th>ID</th><th>License</th><th>Installation ID</th><th>App ID</th><th>Last Seen</th></tr></thead>
      <tbody>{install_rows}</tbody>
    </table>
  </div>
  <script>
    function randChunk() {{
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let out = "";
      for (let i = 0; i < 4; i++) {{
        out += chars[Math.floor(Math.random() * chars.length)];
      }}
      return out;
    }}
    function regenCode() {{
      const el = document.getElementById("license_code");
      if (!el) return;
      el.value = `CECCA-${{randChunk()}}-${{randChunk()}}`;
      el.focus();
      el.select();
    }}
  </script>
</body>
</html>
"""


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/validate", dependencies=[Depends(_auth)])
def validate_license(payload: ValidateIn) -> dict:
    with SessionLocal() as db:
        if payload.code:
            lic = db.scalar(select(License).where(License.code == payload.code))
            if not lic or not lic.active or _is_expired(lic.expires_at):
                return {"ok": False, "reason": "invalid_or_expired"}
            return {"ok": True, "edition": lic.edition}

        if payload.installation_id:
            existing = db.scalars(
                select(Installation).where(
                    Installation.installation_id == payload.installation_id,
                    Installation.app_id == payload.app_id,
                )
            ).first()
            if existing:
                lic = db.scalar(select(License).where(License.code == existing.license_code))
                if not lic or not lic.active or _is_expired(lic.expires_at):
                    return {"ok": False, "reason": "license_revoked_or_expired"}
                existing.last_seen_at = datetime.now(UTC)
                db.commit()
                return {"ok": True, "edition": lic.edition}

            # No linked installation yet -> deny by default.
            # Linking can be done from DB admin panel / manual SQL.
            return {"ok": False, "reason": "installation_not_linked"}

    return {"ok": False, "reason": "invalid_request"}


@app.get("/admin", response_class=HTMLResponse)
def admin_home(_: str = Depends(_admin_auth), message: str = "") -> str:
    with SessionLocal() as db:
        return _render_admin_html(db, message=message)


@app.post("/admin/licenses/create")
def admin_create_license(
    code: str = Form(...),
    edition: str = Form(default="full"),
    max_installations: int = Form(default=1),
    _: str = Depends(_admin_auth),
):
    payload = LicenseCreateIn(code=code.strip(), edition=edition.strip().lower(), max_installations=max_installations)
    with SessionLocal() as db:
        existing = db.scalar(select(License).where(License.code == payload.code))
        if existing:
            return RedirectResponse(url="/admin?message=Licenza+gia+esistente", status_code=303)
        lic = License(
            code=payload.code,
            edition="full" if payload.edition != "demo" else "demo",
            active=True,
            max_installations=payload.max_installations,
        )
        db.add(lic)
        db.commit()
    return RedirectResponse(url="/admin?message=Licenza+creata", status_code=303)


@app.post("/admin/licenses/toggle")
def admin_toggle_license(
    code: str = Form(...),
    active: str = Form(...),
    _: str = Depends(_admin_auth),
):
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.code == code.strip()))
        if not lic:
            return RedirectResponse(url="/admin?message=Licenza+non+trovata", status_code=303)
        lic.active = active.strip().lower() == "true"
        db.commit()
    return RedirectResponse(url="/admin?message=Licenza+aggiornata", status_code=303)


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
