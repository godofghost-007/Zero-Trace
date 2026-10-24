from datetime import UTC, datetime

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(UTC)


class UserAccount(db.Model):
    __tablename__ = "user_accounts"

    id = db.Column(db.String(96), primary_key=True)
    tenant_id = db.Column(db.String(64), nullable=False, default="tenant_local", index=True)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="viewer")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_secret = db.Column(db.String(512), nullable=True)
    mfa_pending_secret = db.Column(db.String(512), nullable=True)


class AuthSession(db.Model):
    __tablename__ = "auth_sessions"

    id = db.Column(db.String(96), primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    user_id = db.Column(db.String(96), db.ForeignKey("user_accounts.id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), nullable=False, index=True)
    csrf_token = db.Column(db.String(128), nullable=False)
    auth_method = db.Column(db.String(32), nullable=False, default="password")
    mfa_verified = db.Column(db.Boolean, nullable=False, default=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.String(96), primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    user_id = db.Column(db.String(96), db.ForeignKey("user_accounts.id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)


class OidcIdentity(db.Model):
    __tablename__ = "oidc_identities"
    __table_args__ = (
        db.UniqueConstraint("issuer", "subject", name="oidc_identity_issuer_subject"),
    )

    id = db.Column(db.String(96), primary_key=True)
    issuer = db.Column(db.String(512), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(96), db.ForeignKey("user_accounts.id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), nullable=False, index=True)
    email = db.Column(db.String(254), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class AuthAuditEvent(db.Model):
    __tablename__ = "auth_audit_events"

    id = db.Column(db.String(96), primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    outcome = db.Column(db.String(32), nullable=False, index=True)
    user_id = db.Column(db.String(96), nullable=True, index=True)
    tenant_id = db.Column(db.String(64), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    detail = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class DemoScenario(db.Model):
    __tablename__ = "demo_scenario"

    id = db.Column(db.String(32), primary_key=True, default="default")
    stage = db.Column(db.Integer, nullable=False, default=0)
    correlation_id = db.Column(db.String(96), nullable=False, default="corr_demo_7a20")
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.String(96), primary_key=True)
    hostname = db.Column(db.String(253), nullable=False, unique=True)
    scope_id = db.Column(db.String(96), nullable=False)
    environment = db.Column(db.String(64), nullable=False)
    services = db.Column(db.JSON, nullable=False, default=list)
    provenance = db.Column(db.String(128), nullable=False, default="fixture_set_a")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class ScanRun(db.Model):
    __tablename__ = "scan_runs"

    id = db.Column(db.String(96), primary_key=True)
    scope_id = db.Column(db.String(96), nullable=False)
    status = db.Column(db.String(32), nullable=False)
    partial = db.Column(db.Boolean, nullable=False, default=False)
    warnings = db.Column(db.JSON, nullable=False, default=list)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class Finding(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.String(96), primary_key=True)
    identifier = db.Column(db.String(64), nullable=False, unique=True)
    title = db.Column(db.String(256), nullable=False)
    cvss = db.Column(db.Float, nullable=False)
    epss = db.Column(db.Float, nullable=False)
    confidence = db.Column(db.String(128), nullable=False)
    cpe = db.Column(db.String(256), nullable=False)
    synthetic = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class ServiceVulnerability(db.Model):
    __tablename__ = "service_vulnerabilities"

    id = db.Column(db.String(96), primary_key=True)
    asset_id = db.Column(db.String(96), db.ForeignKey("assets.id"), nullable=False)
    finding_id = db.Column(db.String(96), db.ForeignKey("vulnerabilities.id"), nullable=False)
    match_method = db.Column(db.String(64), nullable=False)
    confidence = db.Column(db.String(128), nullable=False)
    evidence = db.Column(db.JSON, nullable=False, default=list)
    review_state = db.Column(db.String(32), nullable=False, default="needs_review")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class PatchProposal(db.Model):
    __tablename__ = "patch_proposals"

    id = db.Column(db.String(96), primary_key=True)
    finding_id = db.Column(db.String(96), db.ForeignKey("vulnerabilities.id"), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="proposed")
    review_required = db.Column(db.Boolean, nullable=False, default=True)
    execution_allowed = db.Column(db.Boolean, nullable=False, default=False)
    due_window_hours = db.Column(db.Integer, nullable=False, default=48)
    safe_next_action = db.Column(db.String(512), nullable=False)
    synthetic = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class GuardEvent(db.Model):
    __tablename__ = "guard_events"

    id = db.Column(db.String(96), primary_key=True)
    action = db.Column(db.String(64), nullable=False)
    outcome = db.Column(db.String(32), nullable=False)
    asset_id = db.Column(db.String(96), nullable=False)
    finding_id = db.Column(db.String(96), nullable=False)
    correlation_id = db.Column(db.String(96), nullable=False)
    audit_sequence = db.Column(db.Integer, nullable=False)
    audit_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class ScoreSnapshot(db.Model):
    __tablename__ = "score_snapshots"

    id = db.Column(db.String(96), primary_key=True)
    stage = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Float, nullable=True)
    aei = db.Column(db.Float, nullable=True)
    vui = db.Column(db.Float, nullable=True)
    aiet = db.Column(db.Float, nullable=True)
    components = db.Column(db.JSON, nullable=False, default=dict)
    formula_version = db.Column(db.String(32), nullable=False, default="demo-v1")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class EventOutbox(db.Model):
    __tablename__ = "demo_event_outbox"

    id = db.Column(db.String(96), primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    entity_type = db.Column(db.String(64), nullable=False)
    entity_id = db.Column(db.String(96), nullable=False)
    source = db.Column(db.String(64), nullable=False)
    correlation_id = db.Column(db.String(96), nullable=False, index=True)
    schema_version = db.Column(db.Integer, nullable=False, default=1)
    payload = db.Column(db.JSON, nullable=False, default=dict)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    redis_entry_id = db.Column(db.String(96))
    last_error = db.Column(db.String(512))
    published_at = db.Column(db.DateTime(timezone=True))
