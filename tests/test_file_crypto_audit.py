import hashlib
import os
import shutil

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from app.exceptions.file_cryptography_exceptions import (
    IntegrityError,
    InvalidKeyError,
)
from app.exceptions.file_cryptography_exceptions import (
    PermissionError as FilePermissionError,
)
from app.exceptions.iam_exceptions import UserNotFoundError
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.model.file_model import File, FilePermission, Permission, WrapAlg
from app.model.user_model import Role
from app.service import AuditService, IAMService
from app.service.file_cryptography_service import FileCryptoService

ADMIN_PW = "Admin12345"
BOB_PW = "Bob123456"
TEST_HMAC_KEY = bytes(range(32))


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Serviço de criptografia com workspace isolado e chaves geradas para ADMIN e BOB."""
    monkeypatch.setattr(security, "TIME_COST", 1)
    monkeypatch.setattr(security, "MEMORY_COST", 8)
    monkeypatch.setattr(security, "PARALLELISM", 1)

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(factory, hmac_key=TEST_HMAC_KEY, key_file=str(tmp_path / ".audit_key"))

    iam = IAMService(factory, audit_service=audit)
    iam.bootstrap_admin("admin", ADMIN_PW)
    admin_session = iam.authenticate("admin", ADMIN_PW)

    iam.register_user(admin_session, "bob", BOB_PW, Role.USER)
    bob_session = iam.authenticate("bob", BOB_PW)

    monkeypatch.setattr(
        FileCryptoService, "_get_user_workspace", lambda self, username: str(tmp_path / username)
    )
    (tmp_path / "admin").mkdir()
    (tmp_path / "bob").mkdir()

    crypto = FileCryptoService(factory, iam.sessions, audit)
    crypto.generate_keys(admin_session)
    crypto.generate_keys(bob_session)
    return factory, crypto, audit, admin_session, bob_session, tmp_path


def _last_event(factory, *actions: str) -> AuditLog:
    with factory() as db:
        events = db.scalars(select(AuditLog)).all()
    events = [e for e in events if e.action_type in actions]
    assert events, f"nenhum evento em {actions}"
    return events[-1]


def _source_file(tmp_path, name: str, content: bytes = b"dados secretos") -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def _tamper_last_byte(path: str) -> None:
    """Corrompe o último byte do ciphertext (a tag AES-GCM deixa de conferir)."""
    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(data[:-1] + bytes([data[-1] ^ 0xFF]))


# Registro de eventos de arquivo (05.2) ------------------------------------ #
def test_encrypt_records_success_event(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "relatorio.pdf")

    out = crypto.encrypt_file(session, src)

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "admin"
    assert event.resource_id == src
    assert '"target": "admin"' in event.details
    assert os.path.exists(out)


def test_decrypt_records_success_event(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    crypto.decrypt_file(session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "admin"
    assert event.resource_id == enc_path


def test_encrypt_fail_records_failure_event(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "relatorio.pdf")

    with pytest.raises(UserNotFoundError):
        crypto.encrypt_file(session, src, target_username="fantasma")

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "usuário alvo inexistente"' in event.details


def test_tampered_decrypt_records_integrity_violation(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    _tamper_last_byte(enc_path)

    with pytest.raises(IntegrityError):
        crypto.decrypt_file(session, enc_path)

    decrypt_event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert decrypt_event.status == AuditStatus.FAIL

    alert = _last_event(factory, AuditAction.INTEGRITY_VIOLATION)
    assert alert.status == AuditStatus.FAIL
    assert "GCM" in alert.details


def test_hash_divergence_records_integrity_violation(env):
    """Divergência do hash SHA-256 registrado (04.3) aborta a descriptografia."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    with factory() as db:
        file_row = db.scalars(select(File)).one()
        file_row.sha256_hash = "0" * 64
        db.commit()

    with pytest.raises(IntegrityError):
        crypto.decrypt_file(session, enc_path)

    alert = _last_event(factory, AuditAction.INTEGRITY_VIOLATION)
    assert alert.status == AuditStatus.FAIL
    assert "hash SHA-256" in alert.details


def test_unauthorized_decrypt_records_failure(env):
    """Usuário sem registro em file_permissions não descriptografa (03.2)."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(FilePermissionError):
        crypto.decrypt_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.FAIL
    assert event.username == "bob"
    assert '"reason": "usuário sem permissão sobre o arquivo"' in event.details


def test_missing_private_key_records_failure(env):
    """Desencriptação de arquivo recebido por RSA exige a chave privada."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf"), target_username="bob"
    )
    os.remove(os.path.join(tmp_path, "bob", "private.pem"))

    with pytest.raises(FileNotFoundError):
        crypto.decrypt_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "chave privada ausente no workspace"' in event.details


# Envelope Encryption: metadados e permissões ------------------------------ #
def test_encrypt_keeps_source_file_metadata(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    content = b"dados secretos"
    enc_path = crypto.encrypt_file(
        session, _source_file(tmp_path, "relatorio.pdf", content)
    )

    with factory() as db:
        rows = db.scalars(select(FilePermission)).all()
        assert len(rows) == 1
        assert rows[0].wrap_alg == WrapAlg.KEK.value
        assert rows[0].permission == Permission.MODIFY.value

        file_row = db.get(File, rows[0].file_id)
        assert file_row.sha256_hash == hashlib.sha256(content).hexdigest()
        assert file_row.original_name == "relatorio.pdf"
        assert file_row.encrypted_path == enc_path


def test_target_receives_rsa_dek_and_can_decrypt(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    content = b"segredo para o bob"
    enc_path = crypto.encrypt_file(
        admin_session,
        _source_file(tmp_path, "doc.pdf", content),
        target_username="bob",
    )

    # ... e o autor da cifragem mantém acesso pela própria KEK (cópia do .enc
    # porque a descriptografia consome o arquivo).
    copy_path = str(tmp_path / "copia.pdf.enc")
    shutil.copy(enc_path, copy_path)

    out_path = crypto.decrypt_file(bob_session, enc_path)
    with open(out_path, "rb") as decrypted_file:
        assert decrypted_file.read() == content

    # O alvo recebe a DEK envolvida com a chave pública RSA dele...
    with factory() as db:
        rows = db.scalars(select(FilePermission)).all()
        rsa_rows = [r for r in rows if r.wrap_alg == WrapAlg.RSA.value]
        kek_rows = [r for r in rows if r.wrap_alg == WrapAlg.KEK.value]
        assert len(rsa_rows) == 1
        assert len(kek_rows) == 1
        assert rsa_rows[0].granted_by == admin_session.user_id

    admin_out = crypto.decrypt_file(admin_session, copy_path)
    with open(admin_out, "rb") as decrypted_admin_file:
        assert decrypted_admin_file.read() == content


def test_legacy_encrypted_file_is_rejected(env, tmp_path):
    factory, crypto, audit, session, bob_session, _ = env
    fake_enc = str(tmp_path / "antigo.pdf.enc")
    with open(fake_enc, "wb") as f:
        f.write(b"legado" * 100)

    with pytest.raises(InvalidKeyError):
        crypto.decrypt_file(session, fake_enc)


def test_key_generation_is_audited(env):
    factory, crypto, audit, session, bob_session, _ = env
    event = _last_event(factory, AuditAction.KEYS_GENERATE)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "bob"
    assert event.user_id == bob_session.user_id


def test_file_events_keep_log_integrity(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc = crypto.encrypt_file(session, _source_file(tmp_path, "a.pdf"))
    crypto.encrypt_file(session, _source_file(tmp_path, "b.pdf"))
    crypto.decrypt_file(session, enc)
    assert audit.verify_integrity() == []


# Distinção READ vs MODIFY (04.1) ------------------------------------------ #
def test_modify_replaces_content_and_keeps_grants_valid(env):
    """MODIFY substitui o conteúdo; a DEK não muda, então demais autorizados (dono
    incluso) continuam conseguindo decifrar, e o hash registrado acompanha (04.1)."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    original = b"conteudo original"
    novo = b"conteudo modificado pelo bob"
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", original)
    )
    crypto.share_file(admin_session, enc_path, "bob", Permission.MODIFY)

    out = crypto.update_file(
        bob_session, enc_path, _source_file(tmp_path, "novo.txt", novo)
    )
    assert out == enc_path

    # O dono ainda decifra o novo conteúdo pela KEK dele (DEK preservada)...
    copy_path = str(tmp_path / "copia.pdf.enc")
    shutil.copy(enc_path, copy_path)
    admin_out = crypto.decrypt_file(admin_session, copy_path)
    with open(admin_out, "rb") as decrypted_file:
        assert decrypted_file.read() == novo

    # ...e o hash registrado em `files` corresponde ao novo conteúdo.
    with factory() as db:
        file_row = db.scalars(select(File)).one()
        assert file_row.sha256_hash == hashlib.sha256(novo).hexdigest()
        grants = db.scalars(select(FilePermission)).all()
        assert len(grants) == 2  # dono + bob; nenhum envolvimento perdido

    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "bob"
    assert event.resource_id == enc_path


def test_read_holder_cannot_modify(env):
    """Holder de READ decifra (leitura) mas não modifica (04.1)."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    original = b"original"
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", original)
    )
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)

    with pytest.raises(FilePermissionError):
        crypto.update_file(
            bob_session, enc_path, _source_file(tmp_path, "novo.txt", b"ataque")
        )

    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert event.status == AuditStatus.FAIL
    assert event.username == "bob"
    assert '"reason": "usuário sem permissão de modificação sobre o arquivo"' in event.details

    # Conteúdo e hash permanecem intactos.
    with factory() as db:
        file_row = db.scalars(select(File)).one()
        assert file_row.sha256_hash == hashlib.sha256(original).hexdigest()


def test_user_without_access_cannot_modify(env):
    """Usuário sem qualquer concessão é barrado antes mesmo de tentar (04.1)."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf")
    )

    with pytest.raises(FilePermissionError):
        crypto.update_file(
            bob_session, enc_path, _source_file(tmp_path, "novo.txt", b"novo")
        )

    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "usuário sem permissão sobre o arquivo"' in event.details


def test_modify_of_tampered_file_records_integrity_violation(env):
    """Modificar um .enc adulterado aborta com INTEGRITY_VIOLATION (04.3) e não
    sobrescreve a evidência: o arquivo permanece como estava."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    original = b"original"
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", original)
    )
    _tamper_last_byte(enc_path)
    with open(enc_path, "rb") as enc_file:
        tampered = enc_file.read()

    with pytest.raises(IntegrityError):
        crypto.update_file(
            admin_session, enc_path, _source_file(tmp_path, "novo.txt", b"novo")
        )

    alert = _last_event(factory, AuditAction.INTEGRITY_VIOLATION)
    assert alert.status == AuditStatus.FAIL
    assert "GCM" in alert.details

    # Nada foi gravado: o .enc adulterado segue intacto e os metadados mantêm
    # o hash original.
    with open(enc_path, "rb") as enc_file:
        assert enc_file.read() == tampered
    with factory() as db:
        file_row = db.scalars(select(File)).one()
        assert file_row.sha256_hash == hashlib.sha256(original).hexdigest()


def test_modify_events_keep_log_integrity(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf")
    )
    crypto.share_file(admin_session, enc_path, "bob", Permission.MODIFY)
    crypto.update_file(
        bob_session, enc_path, _source_file(tmp_path, "novo.txt", b"novo conteudo")
    )
    assert audit.verify_integrity() == []


# Compartilhamento (04.2) -------------------------------------------------- #
def test_share_grants_rsa_dek_and_target_decrypts(env):
    """O alvo recebe a DEK envolvida com a chave pública RSA dele e consegue abrir."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    content = b"segredo do admin"
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", content)
    )

    crypto.share_file(admin_session, enc_path, "bob", Permission.MODIFY)

    with factory() as db:
        shared = db.scalars(
            select(FilePermission).where(FilePermission.user_id == bob_session.user_id)
        ).all()
        assert len(shared) == 1
        assert shared[0].permission == Permission.MODIFY.value
        assert shared[0].wrap_alg == WrapAlg.RSA.value
        assert shared[0].granted_by == admin_session.user_id

    out = crypto.decrypt_file(bob_session, enc_path)
    with open(out, "rb") as decrypted_file:
        assert decrypted_file.read() == content

    event = _last_event(factory, AuditAction.FILE_SHARE)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "admin"
    assert '"target": "bob"' in event.details
    assert '"permission": "MODIFY"' in event.details


def test_share_updates_existing_grant(env):
    """Compartilhar de novo para um usuário autorizado apenas atualiza o nível."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf")
    )

    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)
    crypto.share_file(admin_session, enc_path, "bob", Permission.MODIFY)

    with factory() as db:
        rows = db.scalars(select(FilePermission)).all()
        grants = [r for r in rows if r.user_id == bob_session.user_id]
        assert len(grants) == 1
        assert grants[0].permission == Permission.MODIFY.value


def test_share_unknown_target_audits_fail(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(UserNotFoundError):
        crypto.share_file(admin_session, enc_path, "fantasma")

    event = _last_event(factory, AuditAction.FILE_SHARE)
    assert event.status == AuditStatus.FAIL
    assert '"target": "fantasma"' in event.details
    assert '"reason": "usuário alvo inexistente"' in event.details


def test_share_to_self_is_rejected(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(FilePermissionError):
        crypto.share_file(admin_session, enc_path, "admin")


def test_read_holder_cannot_reshare(env):
    """Somente MODIFY (dono incluso) concede acesso a terceiros."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)

    with pytest.raises(FilePermissionError):
        crypto.share_file(bob_session, enc_path, "admin")

    event = _last_event(factory, AuditAction.FILE_SHARE)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "concedente sem permissão de modificação sobre o arquivo"' in event.details


def test_revoke_removes_access(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)

    crypto.revoke_share(admin_session, enc_path, "bob")

    with factory() as db:
        grants = db.scalars(
            select(FilePermission).where(FilePermission.user_id == bob_session.user_id)
        ).all()
        assert grants == []

    with pytest.raises(FilePermissionError):
        crypto.decrypt_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert event.status == AuditStatus.SUCCESS
    assert '"target": "bob"' in event.details


def test_revoke_requires_owner(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)

    with pytest.raises(FilePermissionError):
        crypto.revoke_share(bob_session, enc_path, "admin")

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "revogação restrita ao dono do arquivo"' in event.details


def test_share_and_revoke_events_keep_log_integrity(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)
    crypto.revoke_share(admin_session, enc_path, "bob")
    assert audit.verify_integrity() == []


# Listagem de arquivos acessíveis (03.2) ----------------------------------- #
def test_list_files_without_any_file_returns_empty(env):
    factory, crypto, audit, session, bob_session, tmp_path = env

    assert crypto.list_files(session) == []


def test_list_files_shows_owned_file_as_modify(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    entries = crypto.list_files(session)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.original_name == "doc.pdf"
    assert entry.encrypted_path == enc_path
    assert entry.owner_username == "admin"
    assert entry.is_owner
    assert entry.permission == Permission.MODIFY.value


def test_list_files_shows_shared_file_and_excludes_others(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_admin = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    enc_bob = crypto.encrypt_file(
        bob_session, _source_file(tmp_path, "bob.pdf", b"conteudo do bob")
    )

    crypto.share_file(session, enc_admin, "bob", Permission.READ)

    entries = crypto.list_files(bob_session)
    assert {e.original_name for e in entries} == {"doc.pdf", "bob.pdf"}

    shared = next(e for e in entries if e.original_name == "doc.pdf")
    assert not shared.is_owner
    assert shared.owner_username == "admin"
    assert shared.permission == Permission.READ.value

    own = next(e for e in entries if e.original_name == "bob.pdf")
    assert own.is_owner
    assert own.owner_username == "bob"


def test_list_files_after_revoke_hides_file(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob", Permission.READ)
    crypto.revoke_share(session, enc_path, "bob")

    assert [e.original_name for e in crypto.list_files(bob_session)] == []


def test_list_files_records_file_access_event(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    crypto.encrypt_file(session, _source_file(tmp_path, "a.pdf"))
    crypto.encrypt_file(session, _source_file(tmp_path, "b.pdf"))

    crypto.list_files(session)

    event = _last_event(factory, AuditAction.FILE_ACCESS)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "admin"
    assert '"files": 2' in event.details


def test_list_files_keeps_log_integrity(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.list_files(session)
    assert audit.verify_integrity() == []


# Verificação de integridade isolada (04.3) -------------------------------- #
def test_verify_confirms_integrity_and_keeps_enc_file(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    result = crypto.verify_file(session, enc_path)

    assert result.original_name == "doc.pdf"
    assert result.encrypted_path == enc_path
    assert len(result.sha256_hash) == 64
    # O .enc NÃO é consumido pela verificação (diferente do decrypt).
    assert os.path.exists(enc_path)

    event = _last_event(factory, AuditAction.FILE_VERIFY)
    assert event.status == AuditStatus.SUCCESS
    assert event.username == "admin"
    assert event.resource_id == enc_path


def test_verify_of_tampered_file_records_integrity_violation(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    _tamper_last_byte(enc_path)

    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)

    alert = _last_event(factory, AuditAction.INTEGRITY_VIOLATION)
    assert alert.status == AuditStatus.FAIL
    assert "GCM" in alert.details
    # O .enc adulterado continua em disco para análise; nada foi gravado.
    assert os.path.exists(enc_path)


def test_verify_detects_hash_registered_divergence(env):
    """Divergência do hash SHA-256 registrado (04.3) aborta a verificação."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    with factory() as db:
        file_row = db.scalars(select(File)).one()
        file_row.sha256_hash = "0" * 64
        db.commit()

    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)

    alert = _last_event(factory, AuditAction.INTEGRITY_VIOLATION)
    assert "hash SHA-256" in alert.details


def test_verify_without_permission_records_failure(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(FilePermissionError):
        crypto.verify_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_VERIFY)
    assert event.status == AuditStatus.FAIL
    assert event.username == "bob"
    assert '"reason": "usuário sem permissão sobre o arquivo"' in event.details


def test_verify_fails_after_revoke(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)
    crypto.verify_file(bob_session, enc_path)
    crypto.revoke_share(admin_session, enc_path, "bob")

    with pytest.raises(FilePermissionError):
        crypto.verify_file(bob_session, enc_path)


def test_verify_with_read_permission_succeeds(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)

    result = crypto.verify_file(bob_session, enc_path)

    assert result.original_name == "doc.pdf"
    assert os.path.exists(enc_path)


def test_verify_keeps_log_integrity(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.verify_file(session, enc_path)
    assert audit.verify_integrity() == []