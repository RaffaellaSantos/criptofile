"""Testes do relatório de logs de auditoria para ADMIN (Requisito 05.3)."""

import json
import os

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from app.exceptions.iam_exceptions import (
    AuthenticationError,
    AuthorizationError,
)
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.model.user_model import Role
from app.service import AuditService, IAMService

ADMIN_PW = "Admin12345"
USER_PW = "User12345"
TEST_HMAC_KEY = bytes(range(32))


@pytest.fixture
def factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def audit(factory):
    return AuditService(factory, hmac_key=TEST_HMAC_KEY, key_file="/tmp/.audit_key_test")


@pytest.fixture
def iam(factory, audit, monkeypatch):
    # Parâmetros reduzidos apenas para acelerar os testes.
    monkeypatch.setattr(security, "TIME_COST", 1)
    monkeypatch.setattr(security, "MEMORY_COST", 8)
    monkeypatch.setattr(security, "PARALLELISM", 1)
    svc = IAMService(factory, audit_service=audit)
    svc.bootstrap_admin("admin", ADMIN_PW)
    return svc


def _events(factory):
    with factory() as db:
        return db.scalars(select(AuditLog)).all()


# Acesso ao relatório ------------------------------------------------------ #
def test_admin_reads_complete_report(iam, audit, factory):
    session = iam.authenticate("admin", ADMIN_PW)

    report = iam.audit_report(session)

    # BOOTSTRAP (USER_CREATE) + LOGIN SUCCESS, e este acesso é auditado em seguida.
    assert [e.action_type for e in report] == ["USER_CREATE", "LOGIN"]
    assert [e.username for e in report] == ["admin", "admin"]
    report_events = [e for e in _events(factory) if e.action_type == "AUDIT_REPORT"]
    assert len(report_events) == 1 and report_events[0].status == "SUCCESS"


def test_non_admin_is_denied_and_attempt_is_recorded(iam, audit, factory):
    admin_session = iam.authenticate("admin", ADMIN_PW)
    iam.register_user(admin_session, "bob", USER_PW, Role.USER)

    bob_session = iam.authenticate("bob", USER_PW)
    with pytest.raises(AuthorizationError):
        iam.audit_report(bob_session)

    attempts = [e for e in _events(factory) if e.action_type == "AUDIT_REPORT"]
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.status == "FAIL" and attempt.username == "bob"
    assert "acesso negado" in attempt.details


def test_report_requires_valid_session(iam):
    with pytest.raises(AuthenticationError):
        iam.audit_report(None)


# Filtros ------------------------------------------------------------------ #
def test_report_filters_by_user_and_action(iam, audit):
    audit.record(AuditAction.FILE_ENCRYPT, username="alice", resource_id="a.pdf")
    audit.record(AuditAction.LOGIN, username="bob")
    session = iam.authenticate("admin", ADMIN_PW)

    only_alice = iam.audit_report(session, username="alice")
    assert {e.username for e in only_alice} == {"alice"}

    only_encrypt = iam.audit_report(session, action_type="FILE_ENCRYPT")
    assert {e.action_type for e in only_encrypt} == {"FILE_ENCRYPT"}


# Relação com a integridade do log ----------------------------------------- #
def test_report_events_are_signed(iam, audit, factory):
    session = iam.authenticate("admin", ADMIN_PW)
    iam.audit_report(session)

    # Um novo evento não quebra a verificação; adulterá-lo quebra.
    assert audit.verify_integrity() == []
    with factory() as db:
        event = db.scalar(
            select(AuditLog).where(AuditLog.action_type == AuditAction.AUDIT_REPORT.value)
        )
        event.details = '{"adulterado": true}'
        db.commit()

    assert audit.verify_integrity() != []

# Exportação em JSON/CEF (seção 2.3 da especificação) ---------------------- #
def test_export_json_roundtrip(audit):
    audit.record(
        AuditAction.FILE_ENCRYPT, username="alice", resource_id="a.pdf",
        details={"reason": "ok", "hash": "ab12"},
    )

    payload = json.loads(audit.export_json(audit.list_events()))

    event = next(e for e in payload if e["action_type"] == "FILE_ENCRYPT")
    assert event["username"] == "alice"
    assert event["resource_id"] == "a.pdf"
    assert event["status"] == "SUCCESS"
    assert event["details"] == {"reason": "ok", "hash": "ab12"}
    assert len(event["signature_hmac"]) == 64


def test_export_cef_line_and_fields(audit):
    audit.record(
        AuditAction.FILE_ENCRYPT, username="alice", resource_id="a.pdf",
        details={"reason": "ok"},
    )
    audit.record(AuditAction.INTEGRITY_VIOLATION, username="bob", status=AuditStatus.FAIL)

    lines = audit.export_cef(audit.list_events()).splitlines()
    encrypt = next(l for l in lines if "FILE_ENCRYPT" in l)
    violation = next(l for l in lines if "INTEGRITY_VIOLATION" in l)

    for line in (encrypt, violation):
        assert line.startswith("CEF:0|CriptoFile|CriptoFile CLI|1.0|")
        assert "suser=" in line and "src=127.0.0.1" in line and "shost=" in line
        assert "cs2Label=Outcome" in line
    # Severidades: violação crítica, evento normal informativo.
    assert "|INTEGRITY_VIOLATION|10|" in violation
    assert "|FILE_ENCRYPT|3|" in encrypt
    assert "cs1=a.pdf" in encrypt


def test_export_cef_escapes_special_chars(audit):
    audit.record(
        AuditAction.FILE_ACCESS, username="eve",
        resource_id="weird=name.pdf", details={"x": "a=b\nc"},
    )

    line = next(
        l for l in audit.export_cef(audit.list_events()).splitlines() if "FILE_ACCESS" in l
    )
    assert "cs1=weird\\=name.pdf" in line
    # A quebra de linha nos detalhes é escapada (o evento deve caber em 1 linha).
    assert line.count("\n") == 0
    assert "\\n" in line
