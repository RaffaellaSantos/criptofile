import contextlib
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.core.session import Session, SessionManager
from app.exceptions import (
    IntegrityError,
    InvalidKeyError,
)
from app.exceptions.file_cryptography_exceptions import (
    FileCryptofileError,
    PermissionError as FilePermissionError,
)
from app.exceptions.iam_exceptions import UserNotFoundError
from app.model.audit_log_model import AuditAction, AuditStatus
from app.model.file_model import File, FilePermission, Permission, WrapAlg
from app.model.user_model import User
from app.service.audit_service import AuditService
from app.utils.cryptography_utils import (
    decrypt_with_kek,
    encrypt_with_kek,
    generate_dek,
    generate_priv_pub_key,
    sha256_bytes,
    unwrap_dek_with_private_key,
    wrap_dek_with_public_key,
)
from app.utils.validator import abs_path

logger = logging.getLogger(__name__)

# Formato do arquivo cifrado (.enc):
#   file_id (36 bytes ASCII UUID) + Nonce (12) + Tag (16) + Ciphertext
# A DEK fica fora do arquivo: é entregue por usuário em `file_permissions` (03.2).
@dataclass(frozen=True)
class FileEntry:
    """Arquivo acessível pelo usuário da sessão, conforme `file_permissions`."""

    file_id: str
    original_name: str
    encrypted_path: str
    # Permissão concedida a este usuário: READ ou MODIFY (03.2).
    permission: str
    owner_username: str
    # True quando o acesso vem de ter cifrado o próprio arquivo.
    is_owner: bool


FILE_ID_SIZE = 36
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
ENC_HEADER_SIZE = FILE_ID_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE


@dataclass(frozen=True)
class VerifyResult:
    """Resultado conferido de `verify_file`: o .enc continua intocado em disco."""

    file_id: str
    original_name: str
    encrypted_path: str
    # SHA-256 registrado em `files`, confirmado igual ao do conteúdo (04.3).
    sha256_hash: str


class FileCryptoService:
    """Serviço responsável pelas operações de criptografia de arquivos e gestão de chaves."""

    def __init__(
        self,
        session_factory: Callable[[], DBSession],
        session_manager: SessionManager,
        audit_service: AuditService | None = None,
    ):
        self._db = session_factory
        self.sessions = session_manager
        # Auditoria dos eventos de arquivo (05.2). Reaproveita a instância da
        # CLI quando informada, evitando carregar duas vezes a chave HMAC.
        self.audit = audit_service or AuditService(session_factory)

    def _get_user_workspace(self, username: str) -> str:
        """Retorna o caminho do workspace isolado do usuário, criando-o se não existir."""
        path = abs_path(f"./workspace/{username}")
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def generate_keys(self, session: Session) -> str:
        """
        Gera o par de chaves RSA para o usuário autenticado.
        Salva a chave privada no workspace local e a pública no banco de dados.
        """
        self.sessions.validate(session)

        try:
            priv, pub = generate_priv_pub_key()

            # Salva a chave privada localmente no workspace
            workspace = self._get_user_workspace(session.username)
            priv_path = os.path.join(workspace, "private.pem")

            encrypted_priv = encrypt_with_kek(priv, session.kek)

            with open(priv_path, "wb") as f_priv:
                f_priv.write(encrypted_priv)

            os.chmod(priv_path, 0o600)

            with self._db() as db:
                user = db.scalar(select(User).where(User.username == session.username))
                if not user:
                    raise UserNotFoundError(
                        f"Usuário '{session.username}' não encontrado no banco."
                    )

                user.public_key = pub.decode("utf-8")
                db.commit()

            logger.info(
                "KEYS_GENERATED: Par de chaves gerado para '%s'.", session.username
            )
            self.audit.record(
                AuditAction.KEYS_GENERATE,
                user_id=session.user_id,
                username=session.username,
            )
            return priv_path

        except OSError as e:
            logger.error(
                "ERRO_OS: Falha ao salvar a chave privada para '%s': %s",
                session.username,
                e,
            )
            self.audit.record(
                AuditAction.KEYS_GENERATE,
                user_id=session.user_id,
                username=session.username,
                status=AuditStatus.FAIL,
                details={"reason": "falha ao gravar a chave privada no workspace"},
            )
            raise PermissionError(
                f"Sem privilégios para criar arquivos no workspace: {e}"
            ) from e

    def encrypt_file(
        self,
        session: Session,
        file_path: str,
        target_username: str | None = None,
        output_path: str | None = None,
    ) -> str:
        """
        Encripta um arquivo usando Envelope Encryption (DEK/KEK).

        Calcula o hash SHA-256 do conteúdo original (04.3), gera uma DEK
        AES-256 única para o arquivo e a envolve com a KEK do usuário da
        sessão (e com a chave pública RSA do alvo, quando `-t`). Metadados e
        DEKs envolvidas ficam nas tabelas `files` e `file_permissions`.
        """
        # A CLI devolve `Path` (validate_path); os logs de auditoria só
        # serializam strings. Normaliza antes de qualquer `resource_id`.
        file_path = str(file_path)
        self.sessions.validate(session)
        target = target_username if target_username else session.username

        with self._db() as db:
            user = db.scalar(select(User).where(User.username == target))
            if not user:
                self._audit_encrypt_fail(session, file_path, target, "usuário alvo inexistente")
                raise UserNotFoundError(
                    f"Usuário alvo '{target}' não existe no sistema."
                )
            if target != session.username and not user.public_key:
                self._audit_encrypt_fail(session, file_path, target, "usuário alvo sem chaves geradas")
                raise InvalidKeyError(
                    f"O usuário '{target}' ainda não gerou chaves no sistema."
                )
            target_user = user

        try:
            absolute_path = abs_path(file_path)
            with open(absolute_path, "rb") as source_file:
                plaintext = source_file.read()
        except FileNotFoundError as e:
            logger.error("FILE_NOT_FOUND: Arquivo fonte ausente na encriptação: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "arquivo fonte ausente")
            raise FileNotFoundError(
                "FILE_NOT_FOUND: Arquivo fonte ausente na encriptação: %s", e
            )
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler/escrever arquivo: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "falha de permissão ao ler/escrever")
            raise PermissionError(f"Sem permissão de acesso ao arquivo: {e}") from e

        file_id = str(uuid.uuid4())
        dek = generate_dek()
        original_hash = sha256_bytes(plaintext)

        # Destino do .enc: pedido explicitamente ou workspace do alvo.
        try:
            if output_path:
                final_out = abs_path(output_path)
                os.makedirs(os.path.dirname(final_out), exist_ok=True)
            else:
                workspace = self._get_user_workspace(target)
                final_out = os.path.join(
                    workspace, os.path.basename(absolute_path) + ".enc"
                )
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao criar destino: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "falha de permissão ao ler/escrever")
            raise PermissionError(f"Sem permissão de acesso ao arquivo: {e}") from e

        # Envelope: uma linha de permissão por usuário autorizado. Para o alvo
        # externo usa-se RSA (a KEK dele é desconhecida do remetente); o próprio
        # usuário da sessão mantém a DEK sob a sua KEK.
        permissions = [
            FilePermission(
                file_id=file_id,
                user_id=session.user_id,
                permission=Permission.MODIFY.value,
                wrapped_dek=encrypt_with_kek(dek, session.kek),
                wrap_alg=WrapAlg.KEK.value,
            )
        ]
        if target != session.username:
            try:
                target_dek = wrap_dek_with_public_key(
                    dek, target_user.public_key.encode("utf-8")
                )
            except ValueError as e:
                logger.error("INVALID_KEY: Chave pública de '%s' inválida.", target)
                self._audit_encrypt_fail(
                    session, file_path, target, "chave pública do alvo inválida"
                )
                raise InvalidKeyError(
                    f"A chave pública de '{target}' é inválida ou está corrompida."
                ) from e
            permissions.append(
                FilePermission(
                    file_id=file_id,
                    user_id=target_user.user_id,
                    permission=Permission.MODIFY.value,
                    wrapped_dek=target_dek,
                    wrap_alg=WrapAlg.RSA.value,
                    granted_by=session.user_id,
                )
            )

        try:
            with open(final_out, "wb") as enc_file:
                enc_file.write(
                    file_id.encode("ascii") + encrypt_with_kek(plaintext, dek)
                )
        except OSError as e:
            logger.error("ERRO_OS: Falha ao gravar o arquivo cifrado: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "falha de permissão ao ler/escrever")
            raise PermissionError(f"Sem permissão ao gravar o arquivo cifrado: {e}") from e

        try:
            with self._db() as db:
                db.add(
                    File(
                        file_id=file_id,
                        owner_id=target_user.user_id,
                        original_name=os.path.basename(absolute_path),
                        sha256_hash=original_hash,
                        encrypted_path=final_out,
                    )
                )
                db.add_all(permissions)
                db.commit()
        except Exception:
            # Sem metadados o .enc seria um artefato órfão sem controle de acesso.
            with contextlib.suppress(OSError):
                os.remove(final_out)
            raise

        os.remove(absolute_path)
        logger.info(
            "FILE_ENCRYPTED: '%s' encriptado para '%s' por '%s'.",
            file_path,
            target,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_ENCRYPT,
            user_id=session.user_id,
            username=session.username,
            resource_id=file_path,
            details={"target": target, "output": final_out},
        )
        return final_out

    def _audit_encrypt_fail(
        self, session: Session, file_path: str, target: str, reason: str
    ) -> None:
        self.audit.record(
            AuditAction.FILE_ENCRYPT,
            user_id=session.user_id,
            username=session.username,
            resource_id=file_path,
            status=AuditStatus.FAIL,
            details={"target": target, "reason": reason},
        )

    def decrypt_file(
        self, session: Session, encrypted_path: str, output_path: str | None = None
    ) -> str:
        """
        Desencripta um arquivo para o usuário da sessão.

        Verifica o registro em `file_permissions` (03.2), decifra a DEK com a
        chave adequada (KEK da sessão ou chave privada RSA), valida a tag
        AES-GCM e o hash SHA-256 do conteúdo contra o registrado em `files`
        (04.3). Em caso de divergência, a operação é abortada com um alerta
        `INTEGRITY_VIOLATION` e nada é gravado em disco.
        """
        self.sessions.validate(session)
        file_id, blob = self._read_enc(session, encrypted_path, AuditAction.FILE_DECRYPT)

        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
                self._audit_decrypt_fail(session, encrypted_path, "arquivo sem metadados registrados")
                raise IntegrityError(
                    "O arquivo não possui metadados de integridade no sistema."
                )

            permission = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == session.user_id,
                )
            )
            if permission is None:
                self._audit_decrypt_fail(session, encrypted_path, "usuário sem permissão sobre o arquivo")
                raise FilePermissionError(
                    "Você não tem permissão de acesso a este arquivo."
                )

            original_hash = file_row.sha256_hash
            original_name = file_row.original_name
            wrap_alg = permission.wrap_alg
            wrapped_dek = permission.wrapped_dek

        # Decifra a DEK de acordo com o envolvimento registrado.
        dek = self._unwrapped_dek(
            session,
            wrapped_dek,
            wrap_alg,
            encrypted_path,
            AuditAction.FILE_DECRYPT,
            "DEK do registro inválida para este usuário",
        )

        try:
            plaintext = decrypt_with_kek(blob[FILE_ID_SIZE:], dek)
        except ValueError as e:
            self._integrity_violation(
                session,
                encrypted_path,
                "tag AES-GCM inválida: arquivo adulterado ou destinado a outro usuário",
            )

        if sha256_bytes(plaintext) != original_hash:
            self._integrity_violation(
                session,
                encrypted_path,
                "hash SHA-256 do conteúdo diverge do hash original registrado",
            )

        try:
            if output_path:
                final_out = abs_path(output_path)
                os.makedirs(os.path.dirname(final_out), exist_ok=True)
            else:
                workspace = self._get_user_workspace(session.username)
                final_out = os.path.join(workspace, original_name)
            with open(final_out, "wb") as out_file:
                out_file.write(plaintext)
        except OSError as e:
            logger.error("ERRO_OS: Falha ao gravar o arquivo descriptografado: %s", e)
            self._audit_decrypt_fail(
                session, encrypted_path, "falha de permissão ao gravar o arquivo"
            )
            raise PermissionError(f"Sem permissão ao gravar o arquivo: {e}") from e

        os.remove(abs_path(encrypted_path))
        logger.info(
            "FILE_DECRYPTED: '%s' aberto com sucesso por '%s'.",
            encrypted_path,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_DECRYPT,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"output": final_out},
        )
        return final_out

    def verify_file(self, session: Session, encrypted_path: str) -> VerifyResult:
        """
        Verifica a integridade de um arquivo .enc sem alterá-lo (04.3).

        Mesma validação da descriptografia — tag AES-GCM e hash SHA-256 do
        conteúdo contra o registrado em `files` — mas o conteúdo é apenas
        conferido em memória: nada é gravado, o .enc não é consumido e o
        resultado fica disponível para o dono conferir quando quiser.
        Divergência registra `INTEGRITY_VIOLATION` e aborta.
        """
        self.sessions.validate(session)
        file_id, blob = self._read_enc(session, encrypted_path, AuditAction.FILE_VERIFY)

        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
                self._audit_fail(
                    session, AuditAction.FILE_VERIFY, encrypted_path, "arquivo sem metadados registrados"
                )
                raise IntegrityError(
                    "O arquivo não possui metadados de integridade no sistema."
                )

            permission = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == session.user_id,
                )
            )
            if permission is None:
                self._audit_fail(
                    session, AuditAction.FILE_VERIFY, encrypted_path, "usuário sem permissão sobre o arquivo"
                )
                raise FilePermissionError(
                    "Você não tem permissão de acesso a este arquivo."
                )

            original_hash = file_row.sha256_hash
            original_name = file_row.original_name
            wrap_alg = permission.wrap_alg
            wrapped_dek = permission.wrapped_dek

        dek = self._unwrapped_dek(
            session,
            wrapped_dek,
            wrap_alg,
            encrypted_path,
            AuditAction.FILE_VERIFY,
            "DEK do registro inválida para este usuário",
        )

        try:
            plaintext = decrypt_with_kek(blob[FILE_ID_SIZE:], dek)
        except ValueError as e:
            self._integrity_violation(
                session,
                encrypted_path,
                "tag AES-GCM inválida: arquivo adulterado ou destinado a outro usuário",
                AuditAction.FILE_VERIFY,
            )

        if sha256_bytes(plaintext) != original_hash:
            self._integrity_violation(
                session,
                encrypted_path,
                "hash SHA-256 do conteúdo diverge do hash original registrado",
                AuditAction.FILE_VERIFY,
            )

        logger.info(
            "FILE_VERIFIED: '%s' íntegro na verificação de '%s'.",
            encrypted_path,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_VERIFY,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"sha256": original_hash},
        )
        return VerifyResult(
            file_id=file_id,
            original_name=original_name,
            encrypted_path=encrypted_path,
            sha256_hash=original_hash,
        )

    def update_file(self, session: Session, encrypted_path: str, content_path: str) -> str:
        """
        Substitui o conteúdo de um arquivo .enc existente (04.1).

        Requer permissão MODIFY (o dono sempre tem; holders de READ só leem).
        A DEK do arquivo não muda, então os envolvimentos registrados em
        `file_permissions` continuam válidos para os demais autorizados, e o
        hash SHA-256 em `files` passa a corresponder ao novo conteúdo (04.3).
        Antes de substituir, o conteúdo atual é decifrado e validado (tag GCM
        e hash): divergência registra `INTEGRITY_VIOLATION` e aborta.
        """
        # `-c` chega da CLI como `Path` (validate_path); normaliza para `str`
        # (contrato anotado) antes de ler o arquivo e registrar a auditoria.
        content_path = str(content_path)
        self.sessions.validate(session)
        file_id, blob = self._read_enc(session, encrypted_path, AuditAction.FILE_MODIFY)

        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
                self._audit_fail(
                    session, AuditAction.FILE_MODIFY, encrypted_path, "arquivo sem metadados registrados"
                )
                raise IntegrityError("O arquivo não possui metadados de integridade no sistema.")

            permission = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == session.user_id,
                )
            )
            if permission is None:
                self._audit_fail(
                    session, AuditAction.FILE_MODIFY, encrypted_path, "usuário sem permissão sobre o arquivo"
                )
                raise FilePermissionError("Você não tem permissão de acesso a este arquivo.")
            if permission.permission != Permission.MODIFY.value:
                self._audit_fail(
                    session,
                    AuditAction.FILE_MODIFY,
                    encrypted_path,
                    "usuário sem permissão de modificação sobre o arquivo",
                )
                raise FilePermissionError(
                    "Usuários com permissão de leitura não podem modificar este arquivo."
                )

            original_hash = file_row.sha256_hash
            wrap_alg = permission.wrap_alg
            wrapped_dek = permission.wrapped_dek

        dek = self._unwrapped_dek(
            session,
            wrapped_dek,
            wrap_alg,
            encrypted_path,
            AuditAction.FILE_MODIFY,
            "DEK do registro inválida para este usuário",
        )

        try:
            content_abs = abs_path(content_path)
            with open(content_abs, "rb") as source_file:
                plaintext = source_file.read()
        except OSError as e:
            logger.error("FILE_NOT_FOUND: Arquivo de conteúdo ausente na modificação: %s", e)
            self._audit_fail(
                session, AuditAction.FILE_MODIFY, encrypted_path, "arquivo de conteúdo ausente ou ilegível"
            )
            raise FileNotFoundError(
                f"FILE_NOT_FOUND: Arquivo de conteúdo ausente na modificação: {e}"
            ) from e

        # O conteúdo atual é validado em memória antes da substituição: quem
        # modifica precisa conseguir ler o arquivo, e a adulteração existente
        # é detectada e reportada, não sobreposta (04.3).
        try:
            current = decrypt_with_kek(blob[FILE_ID_SIZE:], dek)
        except ValueError as e:
            self._integrity_violation(
                session,
                encrypted_path,
                "tag AES-GCM inválida: arquivo adulterado ou destinado a outro usuário",
                AuditAction.FILE_MODIFY,
            )

        if sha256_bytes(current) != original_hash:
            self._integrity_violation(
                session,
                encrypted_path,
                "hash SHA-256 do conteúdo diverge do hash original registrado",
                AuditAction.FILE_MODIFY,
            )

        new_hash = sha256_bytes(plaintext)
        try:
            with open(abs_path(encrypted_path), "wb") as enc_file:
                enc_file.write(file_id.encode("ascii") + encrypt_with_kek(plaintext, dek))
        except OSError as e:
            logger.error("ERRO_OS: Falha ao gravar o arquivo cifrado modificado: %s", e)
            self._audit_fail(
                session, AuditAction.FILE_MODIFY, encrypted_path, "falha ao gravar o arquivo cifrado"
            )
            raise PermissionError(f"Sem permissão ao gravar o arquivo cifrado: {e}") from e

        with self._db() as db:
            file_row = db.get(File, file_id)
            file_row.sha256_hash = new_hash
            db.commit()

        logger.info(
            "FILE_MODIFIED: '%s' substituído por '%s'.",
            encrypted_path,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_MODIFY,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"content": content_path},
        )
        return abs_path(encrypted_path)

    def list_files(self, session: Session) -> list[FileEntry]:
        """
        Lista os arquivos aos quais o usuário da sessão tem acesso (03.2).

        A listagem é dada pela linha do próprio usuário em `file_permissions`:
        o dono aparece com MODIFY e quem recebeu acesso via `share` aparece
        com a permissão concedida. O evento `FILE_ACCESS` (05.2) registra a
        consulta.
        """
        self.sessions.validate(session)

        with self._db() as db:
            rows = db.execute(
                select(File, FilePermission, User)
                .join(FilePermission, FilePermission.file_id == File.file_id)
                .join(User, User.user_id == File.owner_id)
                .where(FilePermission.user_id == session.user_id)
                .order_by(File.created_at, File.file_id)
            ).all()
            entries = [
                FileEntry(
                    file_id=file.file_id,
                    original_name=file.original_name,
                    encrypted_path=file.encrypted_path,
                    permission=permission.permission,
                    owner_username=owner.username,
                    is_owner=permission.user_id == file.owner_id,
                )
                for file, permission, owner in rows
            ]

        logger.info(
            "FILE_LISTED: '%s' consultou %d arquivo(s).", session.username, len(entries)
        )
        self.audit.record(
            AuditAction.FILE_ACCESS,
            user_id=session.user_id,
            username=session.username,
            details={"files": len(entries)},
        )
        return entries

    def _read_enc(
        self, session: Session, encrypted_path: str, action: AuditAction
    ) -> tuple[str, bytes]:
        """Lê o .enc e devolve (file_id, blob); falhas são auditadas com `action`."""
        try:
            absolute_path = abs_path(encrypted_path)
            with open(absolute_path, "rb") as enc_file:
                blob = enc_file.read()
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler arquivo encriptado: %s", e)
            self._audit_fail(session, action, encrypted_path, "falha de permissão ao ler arquivo ou chave")
            raise PermissionError(
                f"Sem permissão para ler o arquivo ou a chave: {e}"
            ) from e

        if len(blob) < ENC_HEADER_SIZE:
            self._audit_fail(session, action, encrypted_path, "arquivo .enc truncado ou inválido")
            raise InvalidKeyError("O arquivo .enc está truncado ou tem formato inválido.")

        try:
            return str(uuid.UUID(blob[:FILE_ID_SIZE].decode("ascii"))), blob
        except (ValueError, UnicodeDecodeError) as e:
            self._audit_fail(session, action, encrypted_path, "formato .enc não reconhecido")
            raise InvalidKeyError(
                "Formato de arquivo .enc não reconhecido (cifrado por uma versão anterior do sistema)."
            ) from e

    def _unwrapped_dek(
        self,
        session: Session,
        wrapped_dek: bytes,
        wrap_alg: str,
        encrypted_path: str,
        action: AuditAction,
        fail_reason: str,
    ) -> bytes:
        """Decifra a DEK do usuário da sessão conforme o envolvimento registrado."""
        try:
            if wrap_alg == WrapAlg.KEK.value:
                return decrypt_with_kek(wrapped_dek, session.kek)
            return unwrap_dek_with_private_key(
                wrapped_dek,
                self._load_private_key(session, encrypted_path, action),
            )
        except ValueError as e:
            logger.warning(
                "DEK_FAIL: DEK não confere para '%s' em '%s'.",
                session.username,
                encrypted_path,
            )
            self._audit_fail(session, action, encrypted_path, fail_reason)
            raise InvalidKeyError(
                "A DEK registrada para você neste arquivo é inválida ou foi adulterada."
            ) from e

    def _load_private_key(
        self,
        session: Session,
        encrypted_path: str,
        action: AuditAction = AuditAction.FILE_DECRYPT,
    ) -> bytes:
        """Carrega a chave privada do workspace, decifrada com a KEK da sessão."""
        workspace = self._get_user_workspace(session.username)
        priv_path = os.path.join(workspace, "private.pem")

        if not os.path.exists(priv_path):
            self._audit_fail(session, action, encrypted_path, "chave privada ausente no workspace")
            raise FileNotFoundError(
                f"Chave privada não encontrada em '{priv_path}'. Execute 'genkeys' primeiro."
            )

        with open(priv_path, "rb") as f_key:
            encrypted_priv_bytes = f_key.read()

        try:
            return decrypt_with_kek(encrypted_priv_bytes, session.kek)
        except ValueError as e:
            logger.warning(
                "KEK_FAIL: KEK inválida ou private.pem adulterado para '%s'.",
                session.username,
            )
            self._audit_fail(
                session, action, encrypted_path, "chave privada corrompida ou adulterada"
            )
            raise IntegrityError(
                "Sua chave privada está corrompida ou foi adulterada. Gere as chaves novamente."
            ) from e

    def _audit_fail(
        self, session: Session, action: AuditAction, resource: str, reason: str
    ) -> None:
        self.audit.record(
            action,
            user_id=session.user_id,
            username=session.username,
            resource_id=resource,
            status=AuditStatus.FAIL,
            details={"reason": reason},
        )

    def _integrity_violation(
        self,
        session: Session,
        encrypted_path: str,
        reason: str,
        action: AuditAction = AuditAction.FILE_DECRYPT,
    ) -> None:
        """Registra (FAIL) + INTEGRITY_VIOLATION com `action` e aborta (04.3)."""
        logger.warning(
            "INTEGRITY_FAIL: Operação inválida sobre '%s' por '%s': %s.",
            encrypted_path,
            session.username,
            reason,
        )
        self._audit_fail(
            session, action, encrypted_path, "integridade do arquivo não validada"
        )
        self.audit.record(
            AuditAction.INTEGRITY_VIOLATION,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            status=AuditStatus.FAIL,
            details={"reason": reason},
        )
        raise IntegrityError(
            "A integridade do arquivo foi violada. Operação abortada e evento gravado."
        )

    def _audit_decrypt_fail(
        self, session: Session, encrypted_path: str, reason: str
    ) -> None:
        self._audit_fail(session, AuditAction.FILE_DECRYPT, encrypted_path, reason)

    def share_file(
        self,
        session: Session,
        encrypted_path: str,
        target_username: str,
        permission: Permission = Permission.READ,
    ) -> str:
        """
        Concede a outro usuário acesso a um arquivo .enc (04.2).

        O concedente precisa ter permissão MODIFY (o dono sempre tem). A DEK
        é decifrada com a chave dele e reenvolvida com a chave pública RSA do
        receptor — a KEK deste é desconhecida do concedente, mesmo padrão do
        `encrypt -t` — e a concessão é registrada em `file_permissions`
        (`wrap_alg='RSA'`). Reenvolver para um usuário já autorizado atualiza
        o registro.
        """
        self.sessions.validate(session)

        if target_username == session.username:
            self._audit_share_fail(
                session, encrypted_path, target_username, "o titular já possui acesso ao arquivo"
            )
            raise FilePermissionError("O titular do arquivo já tem acesso a ele.")

        with self._db() as db:
            target_user = db.scalar(select(User).where(User.username == target_username))
        if target_user is None:
            self._audit_share_fail(session, encrypted_path, target_username, "usuário alvo inexistente")
            raise UserNotFoundError(f"Usuário alvo '{target_username}' não existe no sistema.")
        if not target_user.public_key:
            self._audit_share_fail(session, encrypted_path, target_username, "usuário alvo sem chaves geradas")
            raise InvalidKeyError(f"O usuário '{target_username}' ainda não gerou chaves no sistema.")

        file_id = self._read_enc(session, encrypted_path, AuditAction.FILE_SHARE)[0]

        with self._db() as db:
            if db.get(File, file_id) is None:
                self._audit_share_fail(
                    session, encrypted_path, target_username, "arquivo sem metadados registrados"
                )
                raise IntegrityError("O arquivo não possui metadados de integridade no sistema.")

            granter = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == session.user_id,
                )
            )
            if granter is None or granter.permission != Permission.MODIFY.value:
                self._audit_share_fail(
                    session,
                    encrypted_path,
                    target_username,
                    "concedente sem permissão de modificação sobre o arquivo",
                )
                raise FilePermissionError(
                    "Somente usuários com permissão de modificação podem compartilhar este arquivo."
                )
            wrap_alg = granter.wrap_alg
            wrapped_dek = granter.wrapped_dek

        dek = self._unwrapped_dek(
            session,
            wrapped_dek,
            wrap_alg,
            encrypted_path,
            AuditAction.FILE_SHARE,
            "chave do concedente não confere",
        )

        try:
            target_dek = wrap_dek_with_public_key(
                dek, target_user.public_key.encode("utf-8")
            )
        except ValueError as e:
            logger.error("INVALID_KEY: Chave pública de '%s' inválida.", target_username)
            self._audit_share_fail(
                session, encrypted_path, target_username, "chave pública do alvo inválida"
            )
            raise InvalidKeyError(
                f"A chave pública de '{target_username}' é inválida ou está corrompida."
            ) from e

        with self._db() as db:
            existing = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == target_user.user_id,
                )
            )
            if existing:
                existing.permission = permission.value
                existing.wrapped_dek = target_dek
                existing.wrap_alg = WrapAlg.RSA.value
                existing.granted_by = session.user_id
            else:
                db.add(
                    FilePermission(
                        file_id=file_id,
                        user_id=target_user.user_id,
                        permission=permission.value,
                        wrapped_dek=target_dek,
                        wrap_alg=WrapAlg.RSA.value,
                        granted_by=session.user_id,
                    )
                )
            db.commit()

        logger.info(
            "FILE_SHARED: '%s' compartilhado com '%s' (%s).",
            encrypted_path,
            target_username,
            permission.value,
        )
        self.audit.record(
            AuditAction.FILE_SHARE,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"target": target_username, "permission": permission.value},
        )
        return encrypted_path

    def revoke_share(self, session: Session, encrypted_path: str, target_username: str) -> str:
        """Revoga o acesso de outro usuário a um arquivo .enc (04.2). Apenas o dono."""
        self.sessions.validate(session)
        file_id = self._read_enc(session, encrypted_path, AuditAction.FILE_REVOKE)[0]

        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "arquivo sem metadados registrados"
                )
                raise IntegrityError("O arquivo não possui metadados de integridade no sistema.")
            if file_row.owner_id != session.user_id:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "revogação restrita ao dono do arquivo"
                )
                raise FilePermissionError("Somente o dono do arquivo pode revogar acessos.")

            target_user = db.scalar(
                select(User).where(User.username == target_username)
            )
            if target_user is None:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "usuário alvo inexistente"
                )
                raise UserNotFoundError(f"Usuário '{target_username}' não existe no sistema.")
            if target_user.user_id == file_row.owner_id:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "o dono não pode revogar o próprio acesso"
                )
                raise FilePermissionError("O dono do arquivo não pode revogar o próprio acesso.")

            permission = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == target_user.user_id,
                )
            )
            if permission is None:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "usuário sem acesso concedido ao arquivo"
                )
                raise FilePermissionError(
                    f"O usuário '{target_username}' não possui acesso a este arquivo."
                )
            db.delete(permission)
            db.commit()

        logger.info(
            "FILE_REVOKED: acesso de '%s' a '%s' revogado por '%s'.",
            target_username,
            encrypted_path,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_REVOKE,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"target": target_username},
        )
        return encrypted_path

    def _audit_share_fail(
        self, session: Session, encrypted_path: str, target: str, reason: str
    ) -> None:
        self.audit.record(
            AuditAction.FILE_SHARE,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            status=AuditStatus.FAIL,
            details={"target": target, "reason": reason},
        )

    def _audit_revoke_fail(
        self, session: Session, encrypted_path: str, target: str, reason: str
    ) -> None:
        self.audit.record(
            AuditAction.FILE_REVOKE,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            status=AuditStatus.FAIL,
            details={"target": target, "reason": reason},
        )
