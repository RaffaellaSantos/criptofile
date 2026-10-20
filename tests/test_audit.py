import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from app.exceptions.audit_exceptions import AuditError
from app.exceptions.iam_exceptions import AuthenticationError
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.service import AuditService, IAMService
from app.service.audit_service import AUDIT_GENESIS, AUDIT_TRUNCATED

ADMIN_PW = "Admin12345"
TEST_HMAC_KEY = bytes(range(32))


@pytest.fixture
def factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


@pytest.fixture
def audit(factory, tmp_path):
    return AuditService(
        factory, hmac_key=TEST_HMAC_KEY, key_file=str(tmp_path / ".audit_key")
    )


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


def test_foreign_key_fails_verification(audit, factory, tmp_path):
    audit.record(AuditAction.USER_CREATE, username="bob")
    # Mesmo registro visto por outro serviço com chave diferente: a assinatura
    # não confere, provando que a chave realmente participa do HMAC.
    other = AuditService(
        factory, hmac_key=bytes(32), key_file=str(tmp_path / ".audit_key2")
    )
    assert other.verify_integrity() != []


def test_invalid_env_key_raises_audit_error(factory, monkeypatch, tmp_path):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", "zzzz")
    with pytest.raises(AuditError):
        AuditService(factory, key_file=str(tmp_path / ".audit_key3"))


def test_key_file_is_created_and_reused(factory, monkeypatch, tmp_path):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", None)
    key_file = tmp_path / ".audit_key"
    first = AuditService(factory, key_file=str(key_file))
    first.record(AuditAction.LOGIN, username="admin")

    # Um novo processo relê a mesma chave e valida os eventos já assinados.
    second = AuditService(factory, key_file=str(key_file))
    assert len(bytes.fromhex(key_file.read_text())) == 32
    assert second.verify_integrity() == []


@pytest.mark.parametrize(
    "content", ["nao-e-hex", "abcd"], ids=["hex-invalido", "tamanho-errado"]
)
def test_corrupted_key_file_raises_audit_error(factory, monkeypatch, tmp_path, content):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", None)
    key_file = tmp_path / ".audit_key"
    key_file.write_text(content)
    with pytest.raises(AuditError, match="corrompido|bytes"):
        AuditService(factory, key_file=str(key_file))


# Encadeamento dos eventos (detecção de remoção) --------------------------- #
def _chain(factory) -> list[AuditLog]:
    """Eventos na ordem da cadeia, seguindo prev_hmac a partir da gênese."""
    by_prev = {e.prev_hmac: e for e in _events(factory)}
    chain, link = [], AUDIT_GENESIS
    while link in by_prev:
        chain.append(by_prev[link])
        link = chain[-1].signature_hmac
    return chain


def test_events_form_a_signed_chain(audit, factory):
    for name in ("a", "b", "c"):
        audit.record(AuditAction.LOGIN, username=name)

    chain = _chain(factory)
    assert [e.username for e in chain] == ["a", "b", "c"]
    assert chain[0].prev_hmac == AUDIT_GENESIS
    assert chain[1].prev_hmac == chain[0].signature_hmac
    assert audit.verify_integrity() == []


def test_chain_follows_insertion_not_timestamp(audit, factory):
    """Eventos com timestamp retroativo (ex.: testes de janela) seguem encadeados."""
    audit.record(AuditAction.LOGIN, username="a")
    audit.record(
        AuditAction.LOGIN,
        username="b",
        timestamp=datetime.now(UTC) - timedelta(hours=1),
    )
    assert [e.username for e in _chain(factory)] == ["a", "b"]
    assert audit.verify_integrity() == []


def test_deleting_a_middle_event_is_detected(audit, factory):
    for name in ("a", "b", "c"):
        audit.record(AuditAction.LOGIN, username=name)
    with factory() as db:
        db.delete(db.scalar(select(AuditLog).where(AuditLog.username == "b")))
        db.commit()
        successor = db.scalar(select(AuditLog).where(AuditLog.username == "c")).event_id

    assert audit.verify_integrity() == [successor]


def test_relinking_around_a_deleted_event_is_detected(audit, factory):
    """Religar a cadeia sem a chave invalida a assinatura do evento alterado."""
    for name in ("a", "b", "c"):
        audit.record(AuditAction.LOGIN, username=name)
    with factory() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.username == "a"))
        b = db.scalar(select(AuditLog).where(AuditLog.username == "b"))
        c = db.scalar(select(AuditLog).where(AuditLog.username == "c"))
        db.delete(b)
        db.flush()
        c.prev_hmac = a.signature_hmac
        db.commit()
        relinked = c.event_id

    assert audit.verify_integrity() == [relinked]


def test_deleting_the_newest_events_is_detected(audit, factory):
    """A ponta não tem sucessor, mas está registrada fora do banco (.head)."""
    for name in ("a", "b", "c"):
        audit.record(AuditAction.LOGIN, username=name)
    with factory() as db:
        for name in ("b", "c"):
            db.delete(db.scalar(select(AuditLog).where(AuditLog.username == name)))
        db.commit()
    assert audit.verify_integrity() == [AUDIT_TRUNCATED]


def test_truncation_alarm_survives_new_events(audit, factory):
    """Eventos gravados depois do truncamento não apagam a evidência."""
    for name in ("a", "b"):
        audit.record(AuditAction.LOGIN, username=name)
    with factory() as db:
        db.delete(db.scalar(select(AuditLog).where(AuditLog.username == "b")))
        db.commit()

    audit.record(AuditAction.LOGIN, username="depois")
    audit.record(AuditAction.LOGOUT, username="depois")

    assert AUDIT_TRUNCATED in audit.verify_integrity()


def test_head_file_tracks_latest_signature(audit, factory, tmp_path):
    audit.record(AuditAction.LOGIN, username="a")
    audit.record(AuditAction.LOGIN, username="b")
    signature, mac = (tmp_path / ".audit_key.head").read_text().split()
    assert signature == _chain(factory)[-1].signature_hmac
    assert len(mac) == 64
    assert list(tmp_path.glob(".audit_head-*")) == []  # nenhum temporário restante


@pytest.mark.parametrize(
    "content",
    ["lixo", "0" * 64 + " " + "f" * 64],
    ids=["formato-invalido", "mac-forjado"],
)
def test_forged_head_file_is_detected(audit, factory, tmp_path, content):
    audit.record(AuditAction.LOGIN, username="a")
    (tmp_path / ".audit_key.head").write_text(content)
    assert audit.verify_integrity() == [AUDIT_TRUNCATED]


def test_missing_head_file_is_not_an_alarm(audit, factory, tmp_path):
    """Logs anteriores ao registro da ponta (ou sem o arquivo) seguem verificáveis."""
    audit.record(AuditAction.LOGIN, username="a")
    (tmp_path / ".audit_key.head").unlink()
    assert audit.verify_integrity() == []


def test_head_write_failure_does_not_lose_event(factory, tmp_path, caplog):
    audit = AuditService(
        factory,
        hmac_key=TEST_HMAC_KEY,
        key_file=str(tmp_path / ".audit_key"),
        head_file=str(tmp_path / "pasta-inexistente" / "head"),
    )
    audit.record(AuditAction.LOGIN, username="a")
    assert [e.username for e in _events(factory)] == ["a"]
    assert "AUDIT_HEAD" in caplog.text


def test_default_key_file_lives_in_data_dir(factory, monkeypatch, tmp_path):
    """Sem caminho explícito, a chave fica em CRIPTOFILE_HOME, não na pasta atual."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", None)
    monkeypatch.setattr(settings, "CRIPTOFILE_HOME", str(tmp_path / "dados"))
    monkeypatch.chdir(tmp_path)
    AuditService(factory).record(AuditAction.LOGIN, username="a")

    assert (tmp_path / "dados" / ".audit_key").exists()
    assert (tmp_path / "dados" / ".audit_key.head").exists()
    assert not (tmp_path / ".audit_key").exists()


def test_legacy_unchained_events_still_verify(audit, factory):
    """Registros gravados antes do encadeamento (prev_hmac nulo) seguem válidos."""
    legacy = AuditLog(
        event_id="legado-1",
        timestamp=datetime.now(UTC),
        username="antigo",
        action_type="LOGIN",
        status="SUCCESS",
        signature_hmac="",
    )
    legacy.signature_hmac = audit._sign(legacy)
    with factory() as db:
        db.add(legacy)
        db.commit()
    audit.record(AuditAction.LOGIN, username="novo")

    assert audit.verify_integrity() == []
    assert _chain(factory)[0].username == "novo"


def test_concurrent_append_retries_on_new_head(audit, factory, monkeypatch):
    """Duas gravações na mesma ponta: a UNIQUE de prev_hmac rejeita uma, que
    é refeita na ponta nova (a cadeia nunca bifurca)."""
    audit.record(AuditAction.LOGIN, username="a")
    real_head = AuditService._chain_head
    stale = iter([AUDIT_GENESIS])  # primeira tentativa usa uma ponta já ocupada

    monkeypatch.setattr(
        AuditService,
        "_chain_head",
        staticmethod(lambda db: next(stale, None) or real_head(db)),
    )
    audit.record(AuditAction.LOGIN, username="b")

    assert [e.username for e in _chain(factory)] == ["a", "b"]
    assert audit.verify_integrity() == []


def test_append_gives_up_after_repeated_conflicts(audit, factory, monkeypatch):
    audit.record(AuditAction.LOGIN, username="a")
    monkeypatch.setattr(
        AuditService, "_chain_head", staticmethod(lambda db: AUDIT_GENESIS)
    )
    with pytest.raises(AuditError, match="encadear"):
        audit.record(AuditAction.LOGIN, username="b")
