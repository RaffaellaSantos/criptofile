import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.exceptions.audit_exceptions import AuditError
from app.exceptions.iam_exceptions import AuthenticationError
from app.service import AuditService, IAMService

ADMIN_PW = "Admin12345"
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


def _event_by_action(factory, action: str):
    """Retorna o único evento de uma ação no banco (ignora USER_CREATE do bootstrap)."""
    events = [e for e in _events(factory) if e.action_type == action]
    assert len(events) == 1
    return events[0]


# Registro de eventos ------------------------------------------------------ #
def test_record_persists_signed_event(audit, factory):
    ts = datetime.now(UTC)
    audit.record(
        AuditAction.FILE_ENCRYPT,
        username="alice",
        resource_id="doc.pdf",
        timestamp=ts,
        details={"path": "/tmp/doc.pdf"},
    )
    (event,) = _events(factory)

    assert event.action_type == "FILE_ENCRYPT"
    assert event.username == "alice"
    assert event.resource_id == "doc.pdf"
    assert event.status == "SUCCESS"
    # SQLite devolve datetime sem timezone; compara em UTC.
    assert event.timestamp.replace(tzinfo=UTC) == ts
    assert event.details == '{"path": "/tmp/doc.pdf"}'
    # Assinatura HMAC-SHA256 em hex (64 caracteres) + origem registrada.
    assert len(event.signature_hmac) == 64
    assert event.ip_address == "127.0.0.1" and event.hostname


def test_failed_login_of_unknown_user_records_fail_without_user_id(iam, factory):
    with pytest.raises(AuthenticationError):
        iam.authenticate("ghost", "Senha12345")

    event = _event_by_action(factory, "LOGIN")
    assert event.action_type == "LOGIN" and event.status == "FAIL"
    assert event.username == "ghost" and event.user_id is None


def test_login_success_and_logout_are_recorded(iam, factory):
    session = iam.authenticate("admin", ADMIN_PW)
    iam.logout(session)

    login = _event_by_action(factory, "LOGIN")
    logout = _event_by_action(factory, "LOGOUT")
    assert login.status == "SUCCESS" and login.username == "admin"
    assert logout.action_type == "LOGOUT"


# Verificação de integridade ------------------------------------------------ #
def test_verify_integrity_passes_on_untouched_log(audit, iam):
    iam.authenticate("admin", ADMIN_PW)
    with pytest.raises(AuthenticationError):
        iam.authenticate("nobody", ADMIN_PW)  # falha também é registrada

    assert audit.verify_integrity() == []


def test_verify_integrity_detects_tampering(audit, factory):
    audit.record(AuditAction.LOGIN, username="alice")
    audit.record(AuditAction.LOGOUT, username="alice")

    # Adulteração: muda o status de um evento direto no banco.
    with factory() as db:
        event = db.scalar(select(AuditLog).where(AuditLog.action_type == "LOGOUT"))
        event.status = AuditStatus.FAIL
        db.commit()

    forged = audit.verify_integrity()
    assert len(forged) == 1 and forged != []


def test_verify_integrity_detects_deletion_timestamp_change(audit, factory):
    audit.record(AuditAction.USER_CREATE, username="bob")

    # Adulteração: recua o timestamp para apagar a trilha do momento real.
    with factory() as db:
        event = db.scalars(select(AuditLog)).first()
        event.timestamp -= timedelta(hours=1)
        db.commit()

    assert audit.verify_integrity() != []


def test_foreign_key_fails_verification(audit, factory):
    audit.record(AuditAction.USER_CREATE, username="bob")
    # Mesmo registro visto por outro serviço com chave diferente: a assinatura
    # não confere, provando que a chave realmente participa do HMAC.
    other = AuditService(factory, hmac_key=bytes(32), key_file="/tmp/.audit_key_test2")
    assert other.verify_integrity() != []


def test_invalid_env_key_raises_audit_error(factory, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", "zzzz")
    with pytest.raises(AuditError):
        AuditService(factory, key_file="/tmp/.audit_key_test3")