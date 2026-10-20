import hashlib
import os
import pathlib
import shutil
import time
import uuid

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError as SAOperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.database import Base
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from app.exceptions.file_cryptography_exceptions import (
    ConcurrentModificationError,
    FileAlreadyExistsError,
    FileNotFoundError as CryptoFileNotFoundError,
    IntegrityError,
    InvalidKeyError,
)
from app.exceptions.file_cryptography_exceptions import (
    PermissionError as FilePermissionError,
)
from app.exceptions.iam_exceptions import AuthenticationError, UserNotFoundError
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.model.file_model import File, FilePermission, Permission, WrapAlg
from app.model.user_model import Role, User
from app.service import AuditService, IAMService
from app.service import file_cryptography_service as fcs
from app.service.file_cryptography_service import FileCryptoService
from app.utils import cryptography_utils as cu
from app.utils.cryptography_utils import decrypt_stream, decrypt_with_kek, encrypt_with_kek

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
    yield factory, crypto, audit, admin_session, bob_session, tmp_path
    engine.dispose()


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

    with pytest.raises(CryptoFileNotFoundError):
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
    crypto.encrypt_file(
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


# Ciclo de vida dos arquivos e das chaves (03.1) --------------------------- #
def test_encrypt_removes_plaintext_and_decrypt_consumes_enc(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    content = b"dados secretos"
    src = _source_file(tmp_path, "doc.pdf", content)

    enc_path = crypto.encrypt_file(session, src)
    assert not os.path.exists(src)
    assert enc_path == str(tmp_path / "admin" / "doc.pdf.enc")
    with open(enc_path, "rb") as enc_file:
        assert content not in enc_file.read()

    out_path = crypto.decrypt_file(session, enc_path)
    assert out_path == str(tmp_path / "admin" / "doc.pdf")
    assert not os.path.exists(enc_path)
    with open(out_path, "rb") as decrypted_file:
        assert decrypted_file.read() == content


def test_encrypt_and_decrypt_honor_output_path(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_out = str(tmp_path / "saida" / "cifrado.enc")
    plain_out = str(tmp_path / "restaurado" / "doc.pdf")

    assert crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"), output_path=enc_out) == enc_out
    assert crypto.decrypt_file(session, enc_out, output_path=plain_out) == plain_out
    with open(plain_out, "rb") as decrypted_file:
        assert decrypted_file.read() == b"dados secretos"


def test_each_file_gets_its_own_dek(env):
    """Mesmo conteúdo cifrado duas vezes: DEKs, ids e ciphertexts distintos."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    first = crypto.encrypt_file(session, _source_file(tmp_path, "a.pdf", b"igual"))
    second = crypto.encrypt_file(session, _source_file(tmp_path, "b.pdf", b"igual"))

    with open(first, "rb") as f1, open(second, "rb") as f2:
        assert f1.read()[36:] != f2.read()[36:]
    with factory() as db:
        files = db.scalars(select(File)).all()
        deks = [decrypt_with_kek(p.wrapped_dek, session.kek) for p in db.scalars(select(FilePermission))]
    assert files[0].file_id != files[1].file_id
    assert files[0].sha256_hash == files[1].sha256_hash
    assert deks[0] != deks[1]


def test_private_key_is_stored_encrypted_with_kek(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    with open(tmp_path / "admin" / "private.pem", "rb") as key_file:
        stored = key_file.read()

    assert b"PRIVATE KEY" not in stored
    assert decrypt_with_kek(stored, session.kek).startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    with factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
    assert user.public_key.startswith("-----BEGIN PUBLIC KEY-----")


@pytest.mark.parametrize(
    "operation",
    [
        lambda crypto, s, enc: crypto.decrypt_file(s, enc),
        lambda crypto, s, enc: crypto.verify_file(s, enc),
        lambda crypto, s, enc: crypto.share_file(s, enc, "bob"),
        lambda crypto, s, enc: crypto.revoke_share(s, enc, "bob"),
        lambda crypto, s, enc: crypto.list_files(s),
        lambda crypto, s, enc: crypto.generate_keys(s),
    ],
    ids=["decrypt", "verify", "share", "revoke", "list", "genkeys"],
)
def test_operations_require_active_session(env, operation):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.sessions.revoke(session)

    with pytest.raises(AuthenticationError):
        operation(crypto, session, enc_path)
    assert os.path.exists(enc_path)


def test_encrypt_requires_active_session(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf")
    crypto.sessions.revoke(session)

    with pytest.raises(AuthenticationError):
        crypto.encrypt_file(session, src)
    assert os.path.exists(src)


# Tratamento de erros: arquivo e chave inválidos --------------------------- #
def test_encrypt_missing_source_records_failure(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    missing = str(tmp_path / "inexistente.pdf")

    with pytest.raises(CryptoFileNotFoundError, match="inexistente.pdf"):
        crypto.encrypt_file(session, missing)

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "arquivo fonte ausente"' in event.details
    with factory() as db:
        assert db.scalars(select(File)).all() == []


def test_encrypt_to_target_without_keys_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    with factory() as db:
        db.scalar(select(User).where(User.username == "bob")).public_key = None
        db.commit()
    src = _source_file(tmp_path, "doc.pdf")

    with pytest.raises(InvalidKeyError):
        crypto.encrypt_file(session, src, target_username="bob")

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert '"reason": "usuário alvo sem chaves geradas"' in event.details
    assert os.path.exists(src)


def test_encrypt_to_target_with_corrupted_public_key_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    with factory() as db:
        db.scalar(select(User).where(User.username == "bob")).public_key = "chave-invalida"
        db.commit()

    with pytest.raises(InvalidKeyError):
        crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"), target_username="bob")

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert '"reason": "chave pública do alvo inválida"' in event.details


def test_decrypt_missing_enc_records_failure(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    missing = str(tmp_path / "inexistente.pdf.enc")

    with pytest.raises(CryptoFileNotFoundError, match="não encontrado"):
        crypto.decrypt_file(session, missing)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.FAIL
    assert event.resource_id == missing
    assert '"reason": "arquivo .enc inexistente"' in event.details


def test_truncated_enc_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    with open(enc_path, "rb") as enc_file:
        header = enc_file.read()[:40]
    with open(enc_path, "wb") as enc_file:
        enc_file.write(header)

    with pytest.raises(InvalidKeyError):
        crypto.decrypt_file(session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert '"reason": "arquivo .enc truncado ou inválido"' in event.details


def test_enc_without_registered_metadata_is_rejected(env):
    """Um .enc forjado com file_id desconhecido não tem hash de referência."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    forged = str(tmp_path / "forjado.pdf.enc")
    with open(forged, "wb") as enc_file:
        enc_file.write(str(uuid.uuid4()).encode("ascii") + os.urandom(64))

    with pytest.raises(IntegrityError):
        crypto.decrypt_file(session, forged)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert '"reason": "arquivo sem metadados registrados"' in event.details


def test_corrupted_private_key_records_failure(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf"), target_username="bob"
    )
    _tamper_last_byte(str(tmp_path / "bob" / "private.pem"))

    with pytest.raises(IntegrityError):
        crypto.decrypt_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "chave privada corrompida ou adulterada"' in event.details
    assert os.path.exists(enc_path)


def test_tampered_wrapped_dek_is_rejected(env):
    """DEK envolvida adulterada no banco não abre o arquivo (envelope)."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    with factory() as db:
        permission = db.scalars(select(FilePermission)).one()
        permission.wrapped_dek = permission.wrapped_dek[:-1] + bytes([permission.wrapped_dek[-1] ^ 0xFF])
        db.commit()

    with pytest.raises(InvalidKeyError):
        crypto.decrypt_file(session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert '"reason": "DEK do registro inválida para este usuário"' in event.details


def test_update_with_missing_content_records_failure(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    original = b"original"
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", original))

    with pytest.raises(CryptoFileNotFoundError):
        crypto.update_file(session, enc_path, str(tmp_path / "inexistente.txt"))

    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert '"reason": "arquivo de conteúdo ausente ou ilegível"' in event.details
    with factory() as db:
        assert db.scalars(select(File)).one().sha256_hash == hashlib.sha256(original).hexdigest()


# Tratamento de erros: destino já existente (nada é sobrescrito) ---------- #
def test_encrypt_refuses_to_overwrite_existing_enc(env):
    """Cifrar outro arquivo de mesmo nome não destrói o .enc anterior."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"primeiro"))
    (tmp_path / "outra").mkdir()
    second = _source_file(tmp_path / "outra", "doc.pdf", b"segundo")
    with open(enc_path, "rb") as enc_file:
        original_enc = enc_file.read()

    with pytest.raises(FileAlreadyExistsError, match="-o"):
        crypto.encrypt_file(session, second)

    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "arquivo cifrado de destino já existe"' in event.details
    # O .enc anterior, os metadados dele e o arquivo de origem seguem intactos.
    with open(enc_path, "rb") as enc_file:
        assert enc_file.read() == original_enc
    assert os.path.exists(second)
    with factory() as db:
        assert len(db.scalars(select(File)).all()) == 1
        assert len(db.scalars(select(FilePermission)).all()) == 1
    out = crypto.decrypt_file(session, enc_path)
    with open(out, "rb") as decrypted_file:
        assert decrypted_file.read() == b"primeiro"


def test_encrypt_refuses_existing_output_path(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    existing = tmp_path / "ja_existe.enc"
    existing.write_bytes(b"conteudo importante")
    src = _source_file(tmp_path, "doc.pdf")

    with pytest.raises(FileAlreadyExistsError):
        crypto.encrypt_file(session, src, output_path=str(existing))

    assert existing.read_bytes() == b"conteudo importante"
    assert os.path.exists(src)
    with factory() as db:
        assert db.scalars(select(File)).all() == []


def test_decrypt_refuses_to_overwrite_existing_plaintext(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"cifrado"))
    existing = tmp_path / "admin" / "doc.pdf"
    existing.write_bytes(b"versao local")

    with pytest.raises(FileAlreadyExistsError):
        crypto.decrypt_file(session, enc_path)

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "arquivo de destino já existe"' in event.details
    assert existing.read_bytes() == b"versao local"
    # O .enc é preservado: a descriptografia pode ser refeita com outro destino.
    out = crypto.decrypt_file(session, enc_path, output_path=str(tmp_path / "restaurado.pdf"))
    with open(out, "rb") as decrypted_file:
        assert decrypted_file.read() == b"cifrado"


# Tratamento de erros: compartilhamento e revogação (04.2) ----------------- #
def test_share_to_target_without_keys_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    with factory() as db:
        db.scalar(select(User).where(User.username == "bob")).public_key = None
        db.commit()

    with pytest.raises(InvalidKeyError):
        crypto.share_file(session, enc_path, "bob")

    event = _last_event(factory, AuditAction.FILE_SHARE)
    assert '"reason": "usuário alvo sem chaves geradas"' in event.details


def test_revoke_of_user_without_grant_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(FilePermissionError):
        crypto.revoke_share(session, enc_path, "bob")

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert '"reason": "usuário sem acesso concedido ao arquivo"' in event.details


def test_owner_cannot_revoke_own_access(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(FilePermissionError):
        crypto.revoke_share(session, enc_path, "admin")

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert '"reason": "o dono não pode revogar o próprio acesso"' in event.details
    with factory() as db:
        assert len(db.scalars(select(FilePermission)).all()) == 1


def test_revoke_of_unknown_user_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    with pytest.raises(UserNotFoundError):
        crypto.revoke_share(session, enc_path, "fantasma")

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert '"reason": "usuário alvo inexistente"' in event.details


def test_error_events_keep_log_integrity(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    with pytest.raises(FilePermissionError):
        crypto.decrypt_file(bob_session, enc_path)
    with pytest.raises(FilePermissionError):
        crypto.revoke_share(session, enc_path, "bob")
    _tamper_last_byte(enc_path)
    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)
    assert audit.verify_integrity() == []


# Par de chaves: substituição exige --force -------------------------------- #
def _read(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _public_key(factory, username: str) -> str | None:
    with factory() as db:
        return db.scalar(select(User).where(User.username == username)).public_key


def _temp_files(directory) -> list[str]:
    return [name for name in os.listdir(directory) if name.endswith(".tmp")]


def test_genkeys_refuses_to_replace_existing_pair(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    priv_path = tmp_path / "admin" / "private.pem"
    old_priv, old_pub = _read(priv_path), _public_key(factory, "admin")

    with pytest.raises(FileAlreadyExistsError, match="--force"):
        crypto.generate_keys(session)

    assert _read(priv_path) == old_priv
    assert _public_key(factory, "admin") == old_pub
    event = _last_event(factory, AuditAction.KEYS_GENERATE)
    assert event.status == AuditStatus.FAIL
    assert '"reason": "par de chaves já existente"' in event.details


def test_genkeys_refuses_when_only_private_key_exists(env):
    """Chave pública apagada do banco não libera sobrescrever a privada."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    crypto._set_public_key("admin", None)

    with pytest.raises(FileAlreadyExistsError):
        crypto.generate_keys(session)


def test_genkeys_force_replaces_pair_and_old_rsa_files_become_unreadable(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf"), target_username="bob"
    )
    old_pub = _public_key(factory, "bob")

    crypto.generate_keys(bob_session, force=True)

    assert _public_key(factory, "bob") != old_pub
    event = _last_event(factory, AuditAction.KEYS_GENERATE)
    assert event.status == AuditStatus.SUCCESS
    assert '"replaced": true' in event.details
    assert _temp_files(tmp_path / "bob") == []
    # A DEK do arquivo recebido foi envolvida com a chave pública antiga.
    with pytest.raises(InvalidKeyError):
        crypto.decrypt_file(bob_session, enc_path)


def test_genkeys_failure_before_db_keeps_old_pair(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    priv_path = tmp_path / "admin" / "private.pem"
    old_priv, old_pub = _read(priv_path), _public_key(factory, "admin")

    def disk_full(directory, data, kind="enc"):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(fcs, "_write_temp_file", disk_full)
    with pytest.raises(FilePermissionError):
        crypto.generate_keys(session, force=True)

    assert _read(priv_path) == old_priv
    assert _public_key(factory, "admin") == old_pub
    event = _last_event(factory, AuditAction.KEYS_GENERATE)
    assert '"reason": "falha ao gravar a chave privada no workspace"' in event.details


def test_genkeys_failure_after_db_restores_public_key(env, monkeypatch):
    """Falha ao instalar a nova privada reverte a pública: o par segue coerente."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        session, _source_file(tmp_path, "doc.pdf"), target_username="bob"
    )
    old_pub = _public_key(factory, "bob")

    def locked(src, dst):
        raise PermissionError(13, "arquivo em uso")

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "replace", locked)
        with pytest.raises(FilePermissionError):
            crypto.generate_keys(bob_session, force=True)

    assert _public_key(factory, "bob") == old_pub
    assert _temp_files(tmp_path / "bob") == []
    # O par antigo continua válido: o arquivo recebido ainda abre.
    crypto.decrypt_file(bob_session, enc_path)


# Proteção dos arquivos de chave do sistema -------------------------------- #
def test_private_key_cannot_be_encrypted(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    priv_path = str(tmp_path / "admin" / "private.pem")

    with pytest.raises(FilePermissionError, match="chave do sistema"):
        crypto.encrypt_file(session, priv_path)

    assert os.path.exists(priv_path)
    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert '"reason": "arquivo de chave do sistema"' in event.details


def test_audit_key_file_cannot_be_encrypted(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    key_file = tmp_path / ".audit_key"
    key_file.write_text("00" * 32)

    with pytest.raises(FilePermissionError):
        crypto.encrypt_file(session, str(key_file))
    assert key_file.exists()


# Permissões e destino dos arquivos criados -------------------------------- #
@pytest.mark.skipif(os.name == "nt", reason="modo de permissão POSIX")
def test_created_files_are_private_to_owner(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    assert os.stat(enc_path).st_mode & 0o777 == 0o600
    assert os.stat(tmp_path / "admin" / "private.pem").st_mode & 0o777 == 0o600

    out = crypto.decrypt_file(session, enc_path)
    assert os.stat(out).st_mode & 0o777 == 0o600


def test_decrypt_refuses_symlink_at_destination(env):
    """O destino é criado com O_EXCL: um link plantado não desvia a gravação."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    victim = tmp_path / "vitima.txt"
    victim.write_bytes(b"intocado")
    try:
        os.symlink(victim, tmp_path / "admin" / "doc.pdf")
    except (OSError, NotImplementedError):
        pytest.skip("criação de symlink indisponível neste sistema")

    with pytest.raises(FileAlreadyExistsError):
        crypto.decrypt_file(session, enc_path)
    assert victim.read_bytes() == b"intocado"


# Consistência entre disco e banco ----------------------------------------- #
def test_encrypt_db_failure_removes_orphan_enc(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf")

    def failing_factory():
        db = factory()
        commit = db.commit

        def guarded_commit():
            if any(isinstance(obj, File) for obj in db.new):
                raise SAOperationalError("INSERT", {}, Exception("banco indisponível"))
            commit()

        db.commit = guarded_commit
        return db

    monkeypatch.setattr(crypto, "_db", failing_factory)
    with pytest.raises(SAOperationalError):
        crypto.encrypt_file(session, src)

    assert not os.path.exists(tmp_path / "admin" / "doc.pdf.enc")
    assert os.path.exists(src)
    with factory() as db:
        assert db.scalars(select(File)).all() == []


def test_update_leaves_no_temp_files(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"novo"))
    assert _temp_files(tmp_path / "admin") == []


def test_update_replace_failure_keeps_file_and_hash_consistent(env, monkeypatch):
    """Falha ao trocar o .enc reverte o hash: sem falso INTEGRITY_VIOLATION."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"original"))
    original_enc = _read(enc_path)

    def locked(src, dst):
        raise PermissionError(13, "arquivo em uso")

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "replace", locked)
        with pytest.raises(FilePermissionError, match="em uso"):
            crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"novo"))

    assert _read(enc_path) == original_enc
    assert _temp_files(tmp_path / "admin") == []
    result = crypto.verify_file(session, enc_path)
    assert result.sha256_hash == hashlib.sha256(b"original").hexdigest()
    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert '"reason": "falha ao gravar o arquivo cifrado"' in event.details


def test_update_db_failure_keeps_original_enc(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"original"))
    original_enc = _read(enc_path)

    def db_down(file_id, expected_version, **values):
        raise SAOperationalError("UPDATE", {}, Exception("banco indisponível"))

    with monkeypatch.context() as m:
        m.setattr(crypto, "_bump_version", db_down)
        with pytest.raises(SAOperationalError):
            crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"novo"))

    assert _read(enc_path) == original_enc
    assert _temp_files(tmp_path / "admin") == []
    crypto.verify_file(session, enc_path)


# Falhas de E/S ------------------------------------------------------------ #
def _fail_writes(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(fcs, "_new_file", denied)
    monkeypatch.setattr(fcs, "_temp_file", denied)


def test_encrypt_write_failure_keeps_source(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf")
    _fail_writes(monkeypatch)

    with pytest.raises(FilePermissionError):
        crypto.encrypt_file(session, src)

    assert os.path.exists(src)
    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert '"reason": "falha de permissão ao ler/escrever"' in event.details
    with factory() as db:
        assert db.scalars(select(File)).all() == []


def test_decrypt_write_failure_keeps_enc(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _fail_writes(monkeypatch)

    with pytest.raises(FilePermissionError):
        crypto.decrypt_file(session, enc_path)

    assert os.path.exists(enc_path)
    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert '"reason": "falha de permissão ao gravar o arquivo"' in event.details


def test_update_write_failure_keeps_enc(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    original_enc = _read(enc_path)
    _fail_writes(monkeypatch)

    with pytest.raises(FilePermissionError):
        crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"novo"))
    assert _read(enc_path) == original_enc


def test_unreadable_path_is_reported_as_permission_error(env):
    """Ler um diretório como arquivo é falha de E/S, não arquivo inexistente."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    (tmp_path / "pasta").mkdir()

    with pytest.raises(FilePermissionError):
        crypto.encrypt_file(session, str(tmp_path / "pasta"))
    with pytest.raises(FilePermissionError):
        crypto.decrypt_file(session, str(tmp_path / "pasta"))

    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert '"reason": "falha de permissão ao ler arquivo"' in event.details


def test_source_removal_failure_keeps_success(env, monkeypatch, caplog):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf")
    real_remove = os.remove

    def remove(path):
        if os.path.abspath(path) == os.path.abspath(src):
            raise PermissionError(13, "arquivo aberto em outro programa")
        real_remove(path)

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "remove", remove)
        enc_path = crypto.encrypt_file(session, src)

    assert os.path.exists(enc_path) and os.path.exists(src)
    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert event.status == AuditStatus.SUCCESS
    assert '"source_removed": false' in event.details
    assert "Remova-o manualmente" in caplog.text


def test_enc_removal_failure_keeps_decrypt_success(env, monkeypatch, caplog):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"conteudo"))
    real_remove = os.remove

    def remove(path):
        if os.path.abspath(path) == os.path.abspath(enc_path):
            raise PermissionError(13, "arquivo em uso")
        real_remove(path)

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "remove", remove)
        out = crypto.decrypt_file(session, enc_path)

    assert _read(out) == b"conteudo"
    assert os.path.exists(enc_path)
    event = _last_event(factory, AuditAction.FILE_DECRYPT)
    assert event.status == AuditStatus.SUCCESS
    assert '"enc_removed": false' in event.details
    assert "não pôde ser apagado" in caplog.text


# Compartilhamento: chave do alvo e arquivos sem metadados ----------------- #
def test_share_to_target_with_corrupted_public_key_is_rejected(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto._set_public_key("bob", "chave-invalida")

    with pytest.raises(InvalidKeyError):
        crypto.share_file(session, enc_path, "bob")

    event = _last_event(factory, AuditAction.FILE_SHARE)
    assert '"reason": "chave pública do alvo inválida"' in event.details
    with factory() as db:
        assert len(db.scalars(select(FilePermission)).all()) == 1


@pytest.mark.parametrize(
    "operation,action",
    [
        (lambda crypto, s, enc, tmp: crypto.verify_file(s, enc), AuditAction.FILE_VERIFY),
        (lambda crypto, s, enc, tmp: crypto.update_file(s, enc, _source_file(tmp, "n.txt")),
         AuditAction.FILE_MODIFY),
        (lambda crypto, s, enc, tmp: crypto.share_file(s, enc, "bob"), AuditAction.FILE_SHARE),
        (lambda crypto, s, enc, tmp: crypto.revoke_share(s, enc, "bob"), AuditAction.FILE_REVOKE),
    ],
    ids=["verify", "update", "share", "revoke"],
)
def test_forged_enc_is_rejected_by_every_operation(env, operation, action):
    factory, crypto, audit, session, bob_session, tmp_path = env
    forged = str(tmp_path / "forjado.pdf.enc")
    with open(forged, "wb") as enc_file:
        enc_file.write(str(uuid.uuid4()).encode("ascii") + os.urandom(64))

    with pytest.raises(IntegrityError):
        operation(crypto, session, forged, tmp_path)

    event = _last_event(factory, action)
    assert '"reason": "arquivo sem metadados registrados"' in event.details


# Rotação da DEK na revogação ---------------------------------------------- #
CAROL_PW = "Carol12345"


def _add_user(env, username: str, password: str):
    """Cadastra e autentica mais um usuário (com chaves) no mesmo ambiente."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    iam = IAMService(factory, session_manager=crypto.sessions, audit_service=audit)
    iam.register_user(admin_session, username, password, Role.USER)
    session = iam.authenticate(username, password)
    (tmp_path / username).mkdir()
    crypto.generate_keys(session)
    return session


def _dek_of(factory, crypto, session, user_id=None) -> bytes:
    """DEK do (único) arquivo, desenvolvida com a chave do usuário da sessão."""
    with factory() as db:
        grant = db.scalar(
            select(FilePermission).where(FilePermission.user_id == (user_id or session.user_id))
        )
        return crypto._unwrapped_dek(
            session, grant.wrapped_dek, grant.wrap_alg, "-", AuditAction.FILE_DECRYPT, "-"
        )


def _decrypts(crypto, session, enc_path, tmp_path, name: str) -> bytes:
    """Decifra uma cópia do .enc (a descriptografia consome o arquivo)."""
    copy = str(tmp_path / f"{name}.enc")
    shutil.copy(enc_path, copy)
    return _read(crypto.decrypt_file(session, copy, output_path=str(tmp_path / f"{name}.out")))


def test_revoke_rotates_dek_and_old_dek_no_longer_opens_file(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    carol = _add_user(env, "carol", CAROL_PW)
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf", b"segredo"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.READ)
    crypto.share_file(admin_session, enc_path, "carol", Permission.MODIFY)
    # O que bob poderia ter guardado enquanto tinha acesso:
    bob_old_dek = _dek_of(factory, crypto, bob_session)

    crypto.revoke_share(admin_session, enc_path, "bob")

    new_dek = _dek_of(factory, crypto, admin_session)
    assert new_dek != bob_old_dek
    with open(enc_path, "rb") as enc_file:
        enc_file.seek(36)
        with pytest.raises(ValueError):
            decrypt_stream(enc_file, None, bob_old_dek)
    # Quem continua autorizado segue abrindo o arquivo; bob não.
    assert _decrypts(crypto, admin_session, enc_path, tmp_path, "admin") == b"segredo"
    assert _decrypts(crypto, carol, enc_path, tmp_path, "carol") == b"segredo"
    with pytest.raises(FilePermissionError):
        crypto.verify_file(bob_session, enc_path)

    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert '"dek_rotated": true' in event.details
    assert _temp_files(tmp_path / "admin") == []
    assert audit.verify_integrity() == []


def test_revoke_rewraps_with_rsa_for_other_kek_holders(env):
    """O dono (via -t) revoga carol: o autor da cifragem, que tinha a DEK sob a
    própria KEK, passa a recebê-la via RSA e continua com acesso."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    _add_user(env, "carol", CAROL_PW)
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", b"conteudo"), target_username="bob"
    )
    crypto.share_file(bob_session, enc_path, "carol")

    crypto.revoke_share(bob_session, enc_path, "carol")

    with factory() as db:
        algs = {g.user_id: g.wrap_alg for g in db.scalars(select(FilePermission))}
    assert algs == {admin_session.user_id: WrapAlg.RSA.value, bob_session.user_id: WrapAlg.KEK.value}
    assert _decrypts(crypto, admin_session, enc_path, tmp_path, "admin") == b"conteudo"
    assert _decrypts(crypto, bob_session, enc_path, tmp_path, "bob") == b"conteudo"


def test_revoke_aborts_when_remaining_user_has_no_public_key(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    _add_user(env, "carol", CAROL_PW)
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob")
    crypto.share_file(admin_session, enc_path, "carol")
    crypto._set_public_key("carol", None)
    original_enc = _read(enc_path)

    with pytest.raises(InvalidKeyError, match="carol"):
        crypto.revoke_share(admin_session, enc_path, "bob")

    # Nada mudou: bob segue autorizado e o arquivo intacto.
    assert _read(enc_path) == original_enc
    crypto.verify_file(bob_session, enc_path)
    event = _last_event(factory, AuditAction.FILE_REVOKE)
    assert "sem chave pública válida" in event.details


def test_revoke_of_tampered_file_records_violation_and_keeps_grants(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(admin_session, enc_path, "bob")
    _tamper_last_byte(enc_path)

    with pytest.raises(IntegrityError):
        crypto.revoke_share(admin_session, enc_path, "bob")

    assert _last_event(factory, AuditAction.INTEGRITY_VIOLATION).status == AuditStatus.FAIL
    with factory() as db:
        assert len(db.scalars(select(FilePermission)).all()) == 2
    assert _temp_files(tmp_path / "admin") == []


def test_revoke_replace_failure_restores_grants(env, monkeypatch):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf", b"conteudo"))
    crypto.share_file(admin_session, enc_path, "bob")
    original_enc = _read(enc_path)

    def locked(src, dst):
        raise PermissionError(13, "arquivo em uso")

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "replace", locked)
        with pytest.raises(FilePermissionError, match="desfeita"):
            crypto.revoke_share(admin_session, enc_path, "bob")

    assert _read(enc_path) == original_enc
    assert _temp_files(tmp_path / "admin") == []
    # Concessões e DEK antiga restauradas: todos seguem abrindo o arquivo.
    assert _decrypts(crypto, admin_session, enc_path, tmp_path, "admin") == b"conteudo"
    assert _decrypts(crypto, bob_session, enc_path, tmp_path, "bob") == b"conteudo"


# Controle de concorrência ------------------------------------------------- #
def _bump_version_now(factory):
    """Simula outra operação concluída no meio desta."""
    with factory() as db:
        file_row = db.scalars(select(File)).one()
        file_row.version += 1
        db.commit()


def test_update_conflict_is_rejected_without_writing(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"original"))
    original_enc = _read(enc_path)
    real_encrypt = fcs.encrypt_stream

    def concurrent_writer(src, dst, key):
        _bump_version_now(factory)
        return real_encrypt(src, dst, key)

    monkeypatch.setattr(fcs, "encrypt_stream", concurrent_writer)
    with pytest.raises(ConcurrentModificationError):
        crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"novo"))

    assert _read(enc_path) == original_enc
    assert _temp_files(tmp_path / "admin") == []
    event = _last_event(factory, AuditAction.FILE_MODIFY)
    assert '"reason": "alteração simultânea do arquivo"' in event.details


def test_share_conflict_is_rejected_without_granting(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    real_wrap = fcs.wrap_dek_with_public_key

    def concurrent_rotation(dek, pub):
        _bump_version_now(factory)
        return real_wrap(dek, pub)

    monkeypatch.setattr(fcs, "wrap_dek_with_public_key", concurrent_rotation)
    with pytest.raises(ConcurrentModificationError):
        crypto.share_file(session, enc_path, "bob")

    with factory() as db:
        assert len(db.scalars(select(FilePermission)).all()) == 1


def test_revoke_conflict_is_rejected_without_changes(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob")
    original_enc = _read(enc_path)
    real_reencrypt = fcs.reencrypt_stream

    def concurrent_writer(*args):
        _bump_version_now(factory)
        return real_reencrypt(*args)

    monkeypatch.setattr(fcs, "reencrypt_stream", concurrent_writer)
    with pytest.raises(ConcurrentModificationError):
        crypto.revoke_share(session, enc_path, "bob")

    assert _read(enc_path) == original_enc
    crypto.verify_file(bob_session, enc_path)


def test_reader_retries_when_file_is_updated_mid_read(env, monkeypatch):
    """Leitura que cruza com um update legítimo é repetida, sem falso alarme."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf", b"v1"))
    crypto.share_file(admin_session, enc_path, "bob", Permission.MODIFY)
    novo = _source_file(tmp_path, "novo.txt", b"v2")
    real_load = crypto._load_access
    pending = [True]

    def load_then_concurrent_update(session, file_id, *args, **kwargs):
        access = real_load(session, file_id, *args, **kwargs)
        if pending and session is admin_session:
            pending.clear()
            crypto.update_file(bob_session, enc_path, novo)  # entre a leitura e a decifragem
        return access

    monkeypatch.setattr(crypto, "_load_access", load_then_concurrent_update)
    result = crypto.verify_file(admin_session, enc_path)

    assert result.sha256_hash == hashlib.sha256(b"v2").hexdigest()
    with factory() as db:
        assert db.scalars(
            select(AuditLog).where(AuditLog.action_type == AuditAction.INTEGRITY_VIOLATION.value)
        ).all() == []


def test_reader_gives_up_after_repeated_concurrent_changes(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _tamper_last_byte(enc_path)
    versions = iter(range(100, 200))
    monkeypatch.setattr(crypto, "_file_version", lambda file_id: next(versions))

    with pytest.raises(ConcurrentModificationError):
        crypto.verify_file(session, enc_path)

    event = _last_event(factory, AuditAction.FILE_VERIFY)
    assert '"reason": "alteração simultânea do arquivo"' in event.details


def test_every_change_bumps_the_file_version(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    versions = [crypto._file_version(_file_id(factory))]
    crypto.share_file(session, enc_path, "bob")
    versions.append(crypto._file_version(_file_id(factory)))
    crypto.update_file(session, enc_path, _source_file(tmp_path, "n.txt", b"n"))
    versions.append(crypto._file_version(_file_id(factory)))
    crypto.revoke_share(session, enc_path, "bob")
    versions.append(crypto._file_version(_file_id(factory)))
    assert versions == sorted(set(versions))


def _file_id(factory) -> str:
    with factory() as db:
        return db.scalars(select(File)).one().file_id


# Arquivos grandes e formatos anteriores ----------------------------------- #
def test_multi_chunk_file_roundtrip_through_every_operation(env, monkeypatch):
    """Com blocos de 64 bytes, um arquivo de 10 KB passa por cifragem,
    verificação, modificação, rotação e descriptografia em centenas de blocos."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    monkeypatch.setattr(cu, "CHUNK_SIZE", 64)
    first, second = os.urandom(10_000), os.urandom(12_345)

    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "grande.bin", first))
    crypto.verify_file(session, enc_path)
    crypto.share_file(session, enc_path, "bob")
    crypto.update_file(session, enc_path, _source_file(tmp_path, "grande2.bin", second))
    crypto.revoke_share(session, enc_path, "bob")

    assert _read(crypto.decrypt_file(session, enc_path)) == second


def test_legacy_in_memory_enc_and_sha1_dek_still_decrypt(env):
    """Arquivos e concessões gravados antes do streaming e do OAEP-SHA256."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", b"legado"), target_username="bob"
    )
    dek = _dek_of(factory, crypto, admin_session)
    file_id = _file_id(factory)
    with open(enc_path, "wb") as enc_file:  # formato antigo, gravado de uma vez
        enc_file.write(file_id.encode("ascii") + encrypt_with_kek(b"legado", dek))
    with factory() as db:
        grant = db.scalar(select(FilePermission).where(FilePermission.user_id == bob_session.user_id))
        bob_pub = db.scalar(select(User).where(User.username == "bob")).public_key
        grant.wrapped_dek = PKCS1_OAEP.new(RSA.import_key(bob_pub)).encrypt(dek)  # SHA-1
        db.commit()

    assert _read(crypto.decrypt_file(bob_session, enc_path)) == b"legado"


# Sobrescrita do texto claro antes de apagar ------------------------------- #
def test_source_is_overwritten_before_removal(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf", b"segredo de 21 bytes!!")
    seen = {}
    real_remove = os.remove

    def spy_remove(path):
        if os.path.abspath(path) == os.path.abspath(src):
            seen["content"] = _read(path)
        real_remove(path)

    monkeypatch.setattr(fcs.os, "remove", spy_remove)
    crypto.encrypt_file(session, src)

    assert seen["content"] == bytes(21)
    assert not os.path.exists(src)


def test_failed_decrypt_leaves_no_plaintext_behind(env):
    """A decifragem é em blocos para um temporário: se a tag falhar, nem o
    temporário nem o destino reservado ficam em disco."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _tamper_last_byte(enc_path)

    with pytest.raises(IntegrityError):
        crypto.decrypt_file(session, enc_path)

    assert sorted(os.listdir(tmp_path / "admin")) == ["doc.pdf.enc", "private.pem"]


def test_secure_delete_handles_empty_and_unwritable_files(tmp_path, monkeypatch):
    empty = tmp_path / "vazio"
    empty.write_bytes(b"")
    fcs._secure_delete(str(empty))
    assert not empty.exists()

    locked = tmp_path / "bloqueado"
    locked.write_bytes(b"x")
    real_open = open

    def no_write_open(path, mode="r", *args, **kwargs):
        if "+" in mode:
            raise PermissionError(13, "somente leitura")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", no_write_open)
    fcs._secure_delete(str(locked))  # sem acesso para sobrescrever: ainda apaga
    assert not locked.exists()

# Links e diretório de dados ----------------------------------------------- #
def test_symlink_source_is_refused(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "atalho.pdf")
    real_islink = os.path.islink
    monkeypatch.setattr(
        fcs.os.path, "islink", lambda p: os.path.abspath(p) == os.path.abspath(src) or real_islink(p)
    )

    with pytest.raises(FilePermissionError, match="Links simbólicos"):
        crypto.encrypt_file(session, src)

    assert _read(src) == b"dados secretos"
    event = _last_event(factory, AuditAction.FILE_ENCRYPT)
    assert '"reason": "origem é um link simbólico"' in event.details


def test_secure_delete_never_zeroes_a_symlink_target(tmp_path):
    target = tmp_path / "real.txt"
    target.write_bytes(b"conteudo real")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("criação de symlink indisponível neste sistema")

    fcs._secure_delete(str(link))

    assert not os.path.lexists(link)
    assert target.read_bytes() == b"conteudo real"


def test_secure_delete_keeps_other_hardlink_names(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(b"compartilhado")
    other = tmp_path / "outro-nome.txt"
    try:
        os.link(original, other)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink indisponível neste sistema de arquivos")

    fcs._secure_delete(str(original))

    assert not original.exists()
    assert other.read_bytes() == b"compartilhado"


def test_workspace_lives_in_data_dir_not_cwd(monkeypatch, tmp_path):
    """Rodar de outra pasta não pode "perder" a chave privada do usuário."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "CRIPTOFILE_HOME", str(tmp_path / "dados"))
    monkeypatch.chdir(tmp_path)
    workspace = FileCryptoService._get_user_workspace(None, "alice")

    assert workspace == str((tmp_path / "dados" / "workspace" / "alice").resolve())
    assert os.path.isdir(workspace)


# Recuperação de gravações interrompidas (queda do processo) --------------- #
def _simulate_crash_before_replace(final_path, previous: bytes, kind="enc", age=60) -> str:
    """Reproduz o estado deixado por uma queda entre o commit e o os.replace:
    o banco já descreve o conteúdo novo, o arquivo antigo segue no lugar e o
    novo ficou num temporário (antigo o bastante para não ser uma gravação em
    andamento)."""
    directory = os.path.dirname(final_path)
    orphan = os.path.join(directory, f".criptofile-{kind}-queda.tmp")
    os.replace(final_path, orphan)
    with open(final_path, "wb") as f:
        f.write(previous)
    old = time.time() - age
    os.utime(orphan, (old, old))
    return orphan


def _violations(factory) -> list:
    with factory() as db:
        return db.scalars(
            select(AuditLog).where(AuditLog.action_type == AuditAction.INTEGRITY_VIOLATION.value)
        ).all()


def test_interrupted_update_is_recovered_on_next_read(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"v1"))
    before = _read(enc_path)
    crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"v2"))
    orphan = _simulate_crash_before_replace(enc_path, before)

    result = crypto.verify_file(session, enc_path)

    assert result.sha256_hash == hashlib.sha256(b"v2").hexdigest()
    assert not os.path.exists(orphan)
    assert _violations(factory) == []
    event = _last_event(factory, AuditAction.RECOVERY)
    assert "gravação do arquivo cifrado" in event.details


def test_interrupted_revoke_is_recovered_on_next_read(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(admin_session, _source_file(tmp_path, "doc.pdf", b"conteudo"))
    crypto.share_file(admin_session, enc_path, "bob")
    before = _read(enc_path)
    crypto.revoke_share(admin_session, enc_path, "bob")
    _simulate_crash_before_replace(enc_path, before)

    assert _read(crypto.decrypt_file(admin_session, enc_path)) == b"conteudo"
    assert _violations(factory) == []


def test_fresh_temp_is_never_taken_from_a_running_write(env):
    """Temporário recente pode ser de outra gravação em andamento: não é tocado."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"v1"))
    before = _read(enc_path)
    crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"v2"))
    orphan = _simulate_crash_before_replace(enc_path, before, age=0)

    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)
    assert os.path.exists(orphan)


def test_tampering_is_not_masked_by_unrelated_temp_files(env):
    """Só um temporário que confere com a DEK e o hash do banco é instalado."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _tamper_last_byte(enc_path)
    decoy = tmp_path / "admin" / ".criptofile-enc-isca.tmp"
    decoy.write_bytes(_read(enc_path))  # mesmo file_id, conteúdo adulterado
    old = time.time() - 60
    os.utime(decoy, (old, old))

    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)
    assert decoy.exists()
    assert len(_violations(factory)) == 1


def test_interrupted_genkeys_is_recovered_when_rsa_unwrap_fails(env):
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    priv_path = str(tmp_path / "bob" / "private.pem")
    old_priv = _read(priv_path)
    crypto.generate_keys(bob_session, force=True)
    _simulate_crash_before_replace(priv_path, old_priv, kind="key")
    # Cifrado depois da troca: DEK envolvida com a chave pública nova.
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf", b"para o bob"), target_username="bob"
    )

    assert _read(crypto.decrypt_file(bob_session, enc_path)) == b"para o bob"
    assert _read(priv_path) != old_priv
    assert "troca do par de chaves" in _last_event(factory, AuditAction.RECOVERY).details


def test_orphan_plaintext_temps_are_purged_on_decrypt(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    orphan = tmp_path / "admin" / ".criptofile-plain-orfao.tmp"
    orphan.write_bytes(b"texto claro esquecido")
    old = time.time() - 3600
    os.utime(orphan, (old, old))
    in_progress = tmp_path / "admin" / ".criptofile-plain-ativo.tmp"
    in_progress.write_bytes(b"decifragem em andamento")

    crypto.decrypt_file(session, enc_path)

    assert not orphan.exists()
    assert in_progress.exists()


# Ramos de falha restantes ------------------------------------------------- #
def test_encrypt_read_failure_mid_stream_leaves_no_partial_enc(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    src = _source_file(tmp_path, "doc.pdf")

    def broken_stream(src_file, dst, key):
        dst.write(b"parcial")
        raise OSError(5, "erro de E/S no disco")

    monkeypatch.setattr(fcs, "encrypt_stream", broken_stream)
    with pytest.raises(FilePermissionError):
        crypto.encrypt_file(session, src)

    assert not os.path.exists(tmp_path / "admin" / "doc.pdf.enc")
    assert _read(src) == b"dados secretos"


def test_encrypt_destination_that_cannot_be_created(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    (tmp_path / "arquivo-comum").write_bytes(b"x")
    src = _source_file(tmp_path, "doc.pdf")

    with pytest.raises(FilePermissionError):
        crypto.encrypt_file(
            session, src, output_path=str(tmp_path / "arquivo-comum" / "sub" / "a.enc")
        )
    assert os.path.exists(src)


def test_genkeys_for_user_removed_from_db(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    with factory() as db:
        db.delete(db.scalar(select(User).where(User.username == "bob")))
        db.commit()
    with pytest.raises(UserNotFoundError):
        crypto.generate_keys(bob_session, force=True)


def test_decrypt_replace_failure_cleans_up(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    def locked(src, dst):
        raise PermissionError(13, "arquivo em uso")

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "replace", locked)
        with pytest.raises(FilePermissionError):
            crypto.decrypt_file(session, enc_path)

    assert sorted(os.listdir(tmp_path / "admin")) == ["doc.pdf.enc", "private.pem"]


def test_read_failure_mid_stream_is_reported(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))

    def broken(src, dst, key):
        raise OSError(5, "erro de E/S no disco")

    monkeypatch.setattr(fcs, "decrypt_stream", broken)
    with pytest.raises(FilePermissionError, match="E/S"):
        crypto.verify_file(session, enc_path)
    event = _last_event(factory, AuditAction.FILE_VERIFY)
    assert '"reason": "falha de permissão ao ler arquivo"' in event.details


def test_update_validation_crossing_a_change_is_a_conflict(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _tamper_last_byte(enc_path)
    versions = iter(range(100, 200))
    monkeypatch.setattr(crypto, "_file_version", lambda file_id: next(versions))

    with pytest.raises(ConcurrentModificationError):
        crypto.update_file(session, enc_path, _source_file(tmp_path, "n.txt", b"n"))


def test_change_seen_only_after_settle_wait_triggers_reread(env, monkeypatch):
    """Versão igual na hora da falha, diferente após a espera: repete a leitura."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    _tamper_last_byte(enc_path)
    real_version = crypto._file_version
    script = iter([0, 1])  # deslocamento da versão: igual, depois diferente

    monkeypatch.setattr(
        crypto, "_file_version", lambda fid: real_version(fid) + next(script, 0)
    )
    monkeypatch.setattr(fcs, "CONCURRENT_SETTLE_SECONDS", 0)
    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)  # na 2a leitura: adulteração real
    assert len(_violations(factory)) == 1


def test_finalize_failure_does_not_fail_the_update(env, monkeypatch, caplog):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    real_bump = crypto._bump_version
    calls = []

    def bump(file_id, expected_version, **values):
        calls.append(expected_version)
        if len(calls) == 2:  # o incremento de finalização
            raise SAOperationalError("UPDATE", {}, Exception("banco indisponível"))
        return real_bump(file_id, expected_version, **values)

    with monkeypatch.context() as m:
        m.setattr(crypto, "_bump_version", bump)
        crypto.update_file(session, enc_path, _source_file(tmp_path, "n.txt", b"novo"))

    assert "VERSION_FINALIZE" in caplog.text
    # O arquivo e os metadados seguem coerentes apesar da falha na finalização.
    assert crypto.verify_file(session, enc_path).sha256_hash == hashlib.sha256(b"novo").hexdigest()


def test_recovery_ignores_temps_of_other_files(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    other = crypto.encrypt_file(session, _source_file(tmp_path, "outro.pdf"))
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    decoy = tmp_path / "admin" / ".criptofile-enc-outro.tmp"
    decoy.write_bytes(_read(other))
    old = time.time() - 60
    os.utime(decoy, (old, old))
    _tamper_last_byte(enc_path)

    with pytest.raises(IntegrityError):
        crypto.verify_file(session, enc_path)
    assert decoy.exists()


def test_key_recovery_ignores_keys_that_do_not_match(env):
    """Uma chave privada temporária que não corresponde à pública do banco
    (sobra de um genkeys anterior ao commit) não é instalada."""
    factory, crypto, audit, admin_session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(
        admin_session, _source_file(tmp_path, "doc.pdf"), target_username="bob"
    )
    priv, _ = fcs.generate_priv_pub_key()
    stray = tmp_path / "bob" / ".criptofile-key-sobra.tmp"
    stray.write_bytes(encrypt_with_kek(priv, bob_session.kek))
    old = time.time() - 60
    os.utime(stray, (old, old))
    with factory() as db:
        grant = db.scalar(
            select(FilePermission).where(FilePermission.user_id == bob_session.user_id)
        )
        grant.wrapped_dek = grant.wrapped_dek[:-1] + bytes([grant.wrapped_dek[-1] ^ 1])
        db.commit()

    with pytest.raises(InvalidKeyError):
        crypto.decrypt_file(bob_session, enc_path)
    assert stray.exists()


def test_stale_temps_of_missing_directory_is_empty(tmp_path):
    assert fcs._stale_temps(str(tmp_path / "nao-existe"), "enc", 0) == []


def test_revoke_without_owner_grant_is_refused(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob")
    with factory() as db:
        db.delete(
            db.scalar(select(FilePermission).where(FilePermission.user_id == session.user_id))
        )
        db.commit()

    with pytest.raises(FilePermissionError, match="concessão registrada"):
        crypto.revoke_share(session, enc_path, "bob")


def test_revoke_with_hash_divergence_records_violation(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob")
    with factory() as db:
        db.scalars(select(File)).one().sha256_hash = "0" * 64
        db.commit()

    with pytest.raises(IntegrityError):
        crypto.revoke_share(session, enc_path, "bob")
    assert "hash SHA-256" in _last_event(factory, AuditAction.INTEGRITY_VIOLATION).details


def test_revoke_reencrypt_failure_keeps_grants(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob")

    def broken(*args):
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as m:
        m.setattr(fcs, "reencrypt_stream", broken)
        with pytest.raises(FilePermissionError):
            crypto.revoke_share(session, enc_path, "bob")

    with factory() as db:
        assert len(db.scalars(select(FilePermission)).all()) == 2
    assert _temp_files(tmp_path / "admin") == []


def test_revoke_of_tampered_file_crossing_a_change_is_a_conflict(env, monkeypatch):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf"))
    crypto.share_file(session, enc_path, "bob")
    _tamper_last_byte(enc_path)
    versions = iter(range(100, 200))
    monkeypatch.setattr(crypto, "_file_version", lambda file_id: next(versions))

    with pytest.raises(ConcurrentModificationError):
        crypto.revoke_share(session, enc_path, "bob")


# Achados da revisão final ------------------------------------------------- #
def test_revoke_recovers_interrupted_update_then_succeeds(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"v1"))
    crypto.share_file(session, enc_path, "bob")
    before = _read(enc_path)
    crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"v2"))
    _simulate_crash_before_replace(enc_path, before)

    with pytest.raises(ConcurrentModificationError):
        crypto.revoke_share(session, enc_path, "bob")  # recupera e pede nova tentativa
    crypto.revoke_share(session, enc_path, "bob")

    assert _violations(factory) == []
    assert _read(crypto.decrypt_file(session, enc_path)) == b"v2"


def test_writer_does_not_undo_a_temp_installed_by_recovery(env, monkeypatch):
    """Se um leitor já instalou o temporário de um gravador travado, o
    gravador não desfaz a operação (o que dessincronizaria banco e arquivo)."""
    factory, crypto, audit, session, bob_session, tmp_path = env
    enc_path = crypto.encrypt_file(session, _source_file(tmp_path, "doc.pdf", b"v1"))
    real_replace = os.replace

    def installed_by_reader(src, dst):
        real_replace(src, dst)  # o leitor chegou primeiro
        raise FileNotFoundError(2, "temporário não existe mais", src)

    with monkeypatch.context() as m:
        m.setattr(fcs.os, "replace", installed_by_reader)
        crypto.update_file(session, enc_path, _source_file(tmp_path, "novo.txt", b"v2"))

    assert crypto.verify_file(session, enc_path).sha256_hash == hashlib.sha256(b"v2").hexdigest()


def test_audit_head_file_cannot_be_encrypted(env):
    factory, crypto, audit, session, bob_session, tmp_path = env
    head = pathlib.Path(audit._head_file)
    assert head.exists()

    with pytest.raises(FilePermissionError, match="chave do sistema"):
        crypto.encrypt_file(session, str(head))
    assert head.exists()


def test_hardlinked_source_warns_that_content_remains(tmp_path, caplog):
    original = tmp_path / "original.txt"
    original.write_bytes(b"texto claro")
    other = tmp_path / "outro.txt"
    try:
        os.link(original, other)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink indisponível neste sistema de arquivos")

    fcs._secure_delete(str(original))
    assert "HARDLINK" in caplog.text
