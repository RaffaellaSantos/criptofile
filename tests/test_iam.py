import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from app.service import (
    AccountLockedError,
    AuditAction,
    AuditLog,
    AuditStatus,
    AuthenticationError,
    AuthorizationError,
    CredentialValidationError,
    IAMError,
    IAMService,
    Role,
    SessionManager,
    User,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.service.audit_service import AuditService

ADMIN_PW = "Admin12345"
USER_PW = "Alice12345"

# Chave fixa de teste, evita que os testes criem .audit_key no diretório atual.
TEST_HMAC_KEY = bytes(range(32))


@pytest.fixture
def service(monkeypatch, tmp_path):
    # Parâmetros reduzidos apenas para acelerar os testes.
    monkeypatch.setattr(security, "TIME_COST", 1)
    monkeypatch.setattr(security, "MEMORY_COST", 8)
    monkeypatch.setattr(security, "PARALLELISM", 1)

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(
        factory, hmac_key=TEST_HMAC_KEY, key_file=str(tmp_path / ".audit_key")
    )
    svc = IAMService(factory, audit_service=audit)
    svc.bootstrap_admin("admin", ADMIN_PW)
    svc._factory = factory
    yield svc
    engine.dispose()


def _admin(service):
    return service.authenticate("admin", ADMIN_PW)


# 01.1 - Armazenamento seguro --------------------------------------------- #
def test_password_is_not_stored_in_clear_and_salt_is_unique(service):
    service.register_user(_admin(service), "alice", USER_PW)
    with service._factory() as db:
        users = db.scalars(select(User)).all()

    for u in users:
        assert ADMIN_PW not in u.password_hash and USER_PW not in u.password_hash
        assert len(bytes.fromhex(u.salt)) == 16
    assert users[0].salt != users[1].salt


def test_same_password_produces_different_hashes():
    s1, s2 = security.generate_salt(), security.generate_salt()
    assert security.derive_credentials("Senha12345", s1) != security.derive_credentials(
        "Senha12345", s2
    )


def test_kek_is_derived_and_differs_from_stored_hash(service):
    session = _admin(service)
    with service._factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
    assert len(session.kek) == 32
    assert bytes(session.kek).hex() != user.password_hash
    assert "kek" not in repr(session)


# 01.2 - Validação de login ------------------------------------------------ #
def test_login_success(service):
    session = _admin(service)
    assert session.role == Role.ADMIN
    assert service.sessions.validate(session) is session


@pytest.mark.parametrize(
    "username,password", [("admin", "errada123"), ("ghost", ADMIN_PW)]
)
def test_login_failure_has_generic_message(service, username, password):
    with pytest.raises(AuthenticationError, match="Usuário ou senha inválidos"):
        service.authenticate(username, password)


def test_logout_invalidates_session_and_wipes_kek(service):
    session = _admin(service)
    service.logout(session)
    assert not any(session.kek)
    with pytest.raises(AuthenticationError):
        service.list_users(session)


def test_expired_session_is_rejected(service):
    service.sessions = SessionManager(ttl=timedelta(seconds=-1))
    session = _admin(service)
    with pytest.raises(AuthenticationError, match="expirada"):
        service.list_users(session)


def test_forged_session_is_rejected(service):
    session = _admin(service)
    other = SessionManager().create(session.user_id, "admin", Role.ADMIN, b"\x00" * 32)
    with pytest.raises(AuthenticationError):
        service.list_users(other)


# 02.1 - Cadastro apenas por ADMIN ---------------------------------------- #
def test_admin_can_register_user(service):
    info = service.register_user(_admin(service), "alice", USER_PW)
    assert info.role == Role.USER
    assert service.authenticate("alice", USER_PW).role == Role.USER


def test_user_cannot_register_user(service):
    service.register_user(_admin(service), "alice", USER_PW)
    alice = service.authenticate("alice", USER_PW)
    with pytest.raises(AuthorizationError):
        service.register_user(alice, "bob", "Bob1234567")


def test_bootstrap_only_once(service):
    with pytest.raises(IAMError):
        service.bootstrap_admin("root", "Root123456")


def test_duplicate_username(service):
    with pytest.raises(UserAlreadyExistsError):
        service.register_user(_admin(service), "admin", "Outra12345")


@pytest.mark.parametrize(
    "username,password",
    [
        ("ab", USER_PW),
        ("bad name", USER_PW),
        ("carol", "curta1"),
        ("carol", "semnumeros"),
        ("carol123", "carol123"),
    ],
)
def test_credential_policy(service, username, password):
    with pytest.raises(CredentialValidationError):
        service.register_user(_admin(service), username, password)


@pytest.mark.parametrize(
    "username",
    [
        "abc..",
        ".abc",
        "-abc",
        "abc_",
        "...",
        "con",
        "NUL",
        "com1",
        "Lpt9",
        "a" * 33,
        "../etc",
    ],
)
def test_username_must_be_a_safe_directory_name(service, username):
    """O username vira workspace/<username>: nomes que o SO trataria de forma
    especial (pontos finais, dispositivos do Windows, traversal) são recusados."""
    with pytest.raises(CredentialValidationError):
        service.register_user(_admin(service), username, USER_PW)


@pytest.mark.parametrize("username", ["ana", "a.b", "user_1", "Ana-Maria", "console"])
def test_valid_usernames_are_accepted(service, username):
    assert (
        service.register_user(_admin(service), username, USER_PW).username == username
    )


def test_username_uniqueness_ignores_case(service):
    """ "Bob" e "bob" dividiriam o workspace em sistemas case-insensitive."""
    admin = _admin(service)
    service.register_user(admin, "bob", USER_PW)
    with pytest.raises(UserAlreadyExistsError):
        service.register_user(admin, "BOB", USER_PW)
    with pytest.raises(UserAlreadyExistsError):
        service.register_user(admin, "Admin", USER_PW)


def test_password_is_never_logged_or_audited(service, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    service.register_user(_admin(service), "alice", USER_PW)
    with pytest.raises(AuthenticationError):
        service.authenticate("alice", "Errada12345")
    service.authenticate("alice", USER_PW)

    with service._factory() as db:
        details = " ".join(e.details or "" for e in db.scalars(select(AuditLog)))
    for secret in (USER_PW, ADMIN_PW, "Errada12345"):
        assert secret not in caplog.text
        assert secret not in details


# 02.2 - Gestão de acesso apenas por ADMIN -------------------------------- #
def test_admin_can_change_role(service):
    admin = _admin(service)
    service.register_user(admin, "alice", USER_PW)
    assert service.set_role(admin, "alice", Role.ADMIN).role == Role.ADMIN


def test_user_cannot_change_role(service):
    service.register_user(_admin(service), "alice", USER_PW)
    alice = service.authenticate("alice", USER_PW)
    with pytest.raises(AuthorizationError):
        service.set_role(alice, "alice", Role.ADMIN)


def test_cannot_demote_last_admin(service):
    with pytest.raises(IAMError, match="último ADMIN"):
        service.set_role(_admin(service), "admin", Role.USER)


def test_change_role_of_unknown_user(service):
    with pytest.raises(UserNotFoundError):
        service.set_role(_admin(service), "ghost", Role.ADMIN)


def test_user_cannot_list_users(service):
    service.register_user(_admin(service), "alice", USER_PW)
    alice = service.authenticate("alice", USER_PW)
    with pytest.raises(AuthorizationError):
        service.list_users(alice)
    # A tentativa negada deve ser registrada no log de auditoria.
    with service._factory() as db:
        event = db.scalar(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.USER_LIST.value,
                AuditLog.status == AuditStatus.FAIL.value,
            )
        )
    assert event.username == "alice"
    assert "acesso negado" in event.details
    assert [u.username for u in service.list_users(_admin(service))] == [
        "admin",
        "alice",
    ]
    with service._factory() as db:
        success = db.scalar(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.USER_LIST.value,
                AuditLog.status == AuditStatus.SUCCESS.value,
            )
        )
    assert success.username == "admin"
    assert '"users": 2' in success.details


def test_promoted_user_gains_admin_powers(service):
    admin = _admin(service)
    service.register_user(admin, "alice", USER_PW)
    service.set_role(admin, "alice", Role.ADMIN)

    alice = service.authenticate("alice", USER_PW)
    assert service.register_user(alice, "carol", "Carol12345").role == Role.USER
    # Com dois ADMIN, rebaixar um deles passa a ser permitido.
    assert service.set_role(alice, "admin", Role.USER).role == Role.USER


def test_role_change_is_audited(service):
    admin = _admin(service)
    service.register_user(admin, "alice", USER_PW)
    service.set_role(admin, "alice", Role.ADMIN)

    with service._factory() as db:
        event = db.scalar(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.USER_ROLE_CHANGE.value
            )
        )
    assert event.username == "admin"
    assert event.resource_id == "alice"
    assert '"old_role": "USER"' in event.details
    assert '"new_role": "ADMIN"' in event.details


def test_user_creation_is_audited_with_creator(service):
    service.register_user(_admin(service), "alice", USER_PW)
    with service._factory() as db:
        event = db.scalar(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.USER_CREATE.value,
                AuditLog.username == "alice",
            )
        )
    assert event.status == AuditStatus.SUCCESS
    assert '"by": "admin"' in event.details
    assert USER_PW not in event.details


def test_denied_user_creation_is_audited(service):
    service.register_user(_admin(service), "alice", USER_PW)
    alice = service.authenticate("alice", USER_PW)
    with pytest.raises(AuthorizationError):
        service.register_user(alice, "carol", USER_PW)
    with service._factory() as db:
        event = db.scalar(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.USER_CREATE.value,
                AuditLog.status == AuditStatus.FAIL.value,
            )
        )
    assert event.username == "alice"
    assert event.resource_id == "carol"
    assert "acesso negado" in event.details


def test_get_user_requires_session_and_existing_user(service):
    admin = _admin(service)
    assert service.get_user(admin, " admin ").role == Role.ADMIN
    with pytest.raises(UserNotFoundError):
        service.get_user(admin, "ghost")
    service.logout(admin)
    with pytest.raises(AuthenticationError):
        service.get_user(admin, "admin")


def test_has_users_reflects_bootstrap(service):
    assert service.has_users()


# 05.1 - Detecção de força bruta ------------------------------------------- #
def _fails(service, n, username="admin"):
    for _ in range(n):
        with pytest.raises(AuthenticationError):
            service.authenticate(username, "errada123")


def test_lock_blocks_after_four_consecutive_failures(service):
    _fails(service, 4)
    # A conta fica bloqueada mesmo quando a senha informada é a correta.
    with pytest.raises(AccountLockedError, match="bloqueada"):
        service.authenticate("admin", ADMIN_PW)


def test_no_lock_below_threshold(service):
    _fails(service, 3)
    assert service.authenticate("admin", ADMIN_PW).username == "admin"


def test_security_alert_recorded_once_per_outburst(service):
    _fails(service, 4)
    _fails(service, 1)  # tentativa bloqueada não deve gerar novo alerta
    with service._factory() as db:
        alerts = db.scalars(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.SECURITY_ALERT.value
            )
        ).all()
    assert len(alerts) == 1
    assert alerts[0].username == "admin"
    assert "forca_bruta" in alerts[0].details


def test_blocked_login_is_recorded_in_audit_log(service):
    _fails(service, 4)  # emitirá o SECURITY_ALERT e ativa o bloqueio
    with pytest.raises(AccountLockedError, match="bloqueada"):
        service.authenticate("admin", ADMIN_PW)
    with service._factory() as db:
        events = db.scalars(
            select(AuditLog)
            .where(
                AuditLog.action_type == AuditAction.LOGIN.value,
                AuditLog.username == "admin",
            )
            .order_by(AuditLog.timestamp.desc(), AuditLog.event_id.desc())
        ).all()
    last = events[0]
    assert last.status == AuditStatus.FAIL
    assert '"conta_bloqueada"' in last.details


def test_successful_login_resets_counter(service):
    _fails(service, 3)
    service.authenticate("admin", ADMIN_PW)  # SUCCESS zera o contador
    _fails(service, 3)
    # As 3 falhas novas não somam com as antigas: ainda abaixo do limiar.
    assert service.authenticate("admin", ADMIN_PW).username == "admin"


def test_lock_expires_after_window(service):
    for _ in range(4):
        service.audit.record(
            AuditAction.LOGIN,
            username="admin",
            status=AuditStatus.FAIL,
            details={"reason": "senha incorreta"},
            timestamp=datetime.now(UTC) - timedelta(seconds=61),
        )
    # Todas as falhas saíram da janela de 60s: o login volta a funcionar.
    assert service.authenticate("admin", ADMIN_PW).username == "admin"


def test_unknown_user_never_locks_or_alerts(service):
    _fails(service, 4, username="ghost")
    with service._factory() as db:
        alerts = db.scalars(
            select(AuditLog).where(
                AuditLog.action_type == AuditAction.SECURITY_ALERT.value
            )
        ).all()
    assert alerts == []
