import contextlib
import logging
import os
import stat
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import BinaryIO, TypeVar

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as DBSession

from app.core.config import data_dir
from app.core.session import Session, SessionManager
from app.exceptions import (
    IntegrityError,
    InvalidKeyError,
)
from app.exceptions.file_cryptography_exceptions import (
    ConcurrentModificationError,
    FileAlreadyExistsError,
    FileNotFoundError as CryptoFileNotFoundError,
    PermissionError as FilePermissionError,
)
from app.exceptions.iam_exceptions import UserNotFoundError
from app.model.audit_log_model import AuditAction, AuditStatus
from app.model.file_model import File, FilePermission, Permission, WrapAlg
from app.model.user_model import User
from app.service.audit_service import AuditService
from app.utils.cryptography_utils import (
    CHUNK_SIZE,
    decrypt_stream,
    decrypt_with_kek,
    encrypt_stream,
    encrypt_with_kek,
    generate_dek,
    generate_priv_pub_key,
    public_key_of,
    reencrypt_stream,
    unwrap_dek_with_private_key,
    wrap_dek_with_public_key,
)

T = TypeVar("T")
# Tentativas de uma leitura que cruzou com uma alteração simultânea, e a
# espera antes de concluir que uma falha de integridade é adulteração.
CONCURRENT_RETRIES = 3
CONCURRENT_SETTLE_SECONDS = 0.2
TEMP_PREFIX = ".criptofile-"
# Um temporário cifrado só é candidato à recuperação depois desta idade: o
# de uma gravação em andamento (entre o commit e o os.replace) é mais novo.
RECOVERY_MIN_AGE_SECONDS = 5
# Texto claro temporário mais antigo que isto é sobra de processo interrompido.
STALE_PLAINTEXT_SECONDS = 600
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
PRIVATE_KEY_NAME = "private.pem"

# Arquivos criados pelo sistema (texto claro decifrado, .enc, chave privada)
# ficam legíveis apenas pelo dono no SO, independentemente do umask.
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)


@contextlib.contextmanager
def _new_file(path: str) -> Iterator[BinaryIO]:
    """Cria `path` com permissão 0600 e o entrega aberto; nunca sobrescreve
    (FileExistsError). Se o bloco falhar, o arquivo parcial é descartado.

    O_EXCL também recusa um symlink pré-existente no destino, evitando que a
    gravação seja desviada para outro arquivo.
    """
    fd = os.open(path, _NEW_FILE_FLAGS, 0o600)
    try:
        with os.fdopen(fd, "wb") as new_file:
            yield new_file
    except BaseException:
        _discard(path)
        raise


@contextlib.contextmanager
def _temp_file(directory: str, kind: str = "enc") -> Iterator[tuple[BinaryIO, str]]:
    """Temporário 0600 em `directory` (mesmo volume do destino, para que
    `os.replace` seja atômico). Entrega (arquivo, caminho); se o bloco falhar,
    o temporário é sobrescrito e apagado.

    `kind` vai no nome (".criptofile-<kind>-*.tmp"): "enc" (conteúdo cifrado),
    "key" (chave privada) ou "plain" (texto claro ainda não validado). É o que
    permite recuperar uma gravação interrompida e limpar texto claro órfão.
    """
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=f"{TEMP_PREFIX}{kind}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as tmp_file:
            yield tmp_file, tmp_path
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
    except BaseException:
        _discard(tmp_path)
        raise


def _write_temp_file(directory: str, data: bytes, kind: str = "enc") -> str:
    """Grava `data` num temporário (ver `_temp_file`) e devolve o caminho."""
    with _temp_file(directory, kind) as (tmp_file, tmp_path):
        tmp_file.write(data)
    return tmp_path


def _secure_delete(path: str) -> None:
    """Sobrescreve o conteúdo com zeros antes de apagar o arquivo.

    Evita que o texto claro continue recuperável nos mesmos blocos do disco
    após o `os.remove`. É melhor esforço: SSDs (wear leveling), sistemas de
    arquivos copy-on-write e sincronização em nuvem podem guardar cópias fora
    do alcance do processo.
    """
    info = None
    with contextlib.suppress(OSError):
        info = os.lstat(path)
    # Link simbólico: abrir seguiria o link e zeraria o arquivo de destino.
    # Vários nomes (hardlink): zerar apagaria o conteúdo dos outros nomes.
    # Nos dois casos só o nome é removido.
    if info is not None and info.st_nlink > 1 and not stat.S_ISLNK(info.st_mode):
        logger.warning(
            "HARDLINK: '%s' tem outros nomes no disco; só este nome será removido e "
            "o conteúdo continua acessível pelos demais.",
            path,
        )
    if info is not None and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1:
        try:
            with open(path, "r+b") as target:
                zeros = bytes(min(info.st_size, CHUNK_SIZE))
                remaining = info.st_size
                while remaining > 0:
                    written = min(remaining, len(zeros))
                    target.write(zeros[:written])
                    remaining -= written
                target.flush()
                os.fsync(target.fileno())
        except OSError:
            pass  # sem acesso para sobrescrever: ainda tenta apagar
    os.remove(path)


def _stale_temps(directory: str, kind: str, min_age: float) -> list[str]:
    """Temporários de `kind` em `directory` sem modificação há `min_age` s.

    A idade separa sobras de um processo interrompido das gravações em
    andamento de outro processo, que nunca devem ser tocadas.
    """
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    now = time.time()
    stale = []
    for name in names:
        if not (name.startswith(f"{TEMP_PREFIX}{kind}-") and name.endswith(".tmp")):
            continue
        path = os.path.join(directory, name)
        with contextlib.suppress(OSError):
            if now - os.path.getmtime(path) >= min_age:
                stale.append(path)
    return stale


def _installed_by_recovery(tmp_path: str, error: OSError) -> bool:
    """O `os.replace` falhou porque o temporário não existe mais: um leitor já
    o instalou no lugar do .enc (recuperação de gravação travada). Arquivo e
    banco estão coerentes; desfazer a operação agora os dessincronizaria."""
    if isinstance(error, FileNotFoundError) and not os.path.exists(tmp_path):
        logger.info("RECOVERED_BY_READER: '%s' já foi instalado por outro processo.", tmp_path)
        return True
    return False


def _discard(path: str) -> None:
    """Apaga (com sobrescrita) um arquivo parcial ou temporário; nunca levanta."""
    with contextlib.suppress(OSError):
        _secure_delete(path)


class _ConcurrentChange(Exception):
    """Uso interno: a leitura cruzou com uma alteração simultânea do arquivo."""


class _ValidationFailed(Exception):
    """Uso interno: aborta um bloco de gravação para descartar o temporário."""


@dataclass(frozen=True)
class VerifyResult:
    """Resultado conferido de `verify_file`: o .enc continua intocado em disco."""

    file_id: str
    original_name: str
    encrypted_path: str
    # SHA-256 registrado em `files`, confirmado igual ao do conteúdo (04.3).
    sha256_hash: str


@dataclass(frozen=True)
class _Access:
    """Metadados do arquivo e a concessão do usuário da sessão, lidos juntos."""

    original_name: str
    sha256_hash: str
    version: int
    permission: str
    wrap_alg: str
    wrapped_dek: bytes


def _grant_snapshot(grant: FilePermission) -> dict:
    return {
        column: getattr(grant, column)
        for column in ("file_id", "user_id", "permission", "wrapped_dek",
                       "wrap_alg", "granted_by", "created_at")
    }


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
        path = str(data_dir() / "workspace" / username)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def generate_keys(self, session: Session, force: bool = False) -> str:
        """
        Gera o par de chaves RSA para o usuário autenticado.
        Salva a chave privada no workspace local e a pública no banco de dados.

        Substituir um par existente torna ilegíveis os arquivos recebidos via
        RSA (`encrypt -t`/`share`), cujas DEKs foram envolvidas com a chave
        pública antiga; por isso exige `force=True`.
        """
        self.sessions.validate(session)

        with self._db() as db:
            user = db.scalar(select(User).where(User.username == session.username))
            if not user:
                raise UserNotFoundError(f"Usuário '{session.username}' não encontrado no banco.")
            old_public_key = user.public_key
            has_public_key = bool(old_public_key)

        tmp_path = None
        public_key_committed = False
        try:
            workspace = self._get_user_workspace(session.username)
            priv_path = os.path.join(workspace, PRIVATE_KEY_NAME)

            if not force and (has_public_key or os.path.exists(priv_path)):
                self._audit_keys_fail(session, "par de chaves já existente")
                raise FileAlreadyExistsError(
                    f"'{session.username}' já possui um par de chaves. Gerar outro torna "
                    "ilegíveis os arquivos recebidos de outros usuários; use --force "
                    "somente se a chave atual foi perdida."
                )

            priv, pub = generate_priv_pub_key()
            # A chave privada vai primeiro para um temporário 0600: a antiga só
            # é substituída depois que a nova pública estiver gravada no banco,
            # de modo que uma falha não deixa o par dessincronizado.
            tmp_path = _write_temp_file(workspace, encrypt_with_kek(priv, session.kek), kind="key")

            self._set_public_key(session.username, pub.decode("utf-8"))
            public_key_committed = True

            os.replace(tmp_path, priv_path)
            tmp_path = None
        except OSError as e:
            if public_key_committed:
                # A chave privada antiga continua no disco: restaura a pública
                # correspondente para o par não ficar dessincronizado.
                self._set_public_key(session.username, old_public_key)
            logger.error(
                "ERRO_OS: Falha ao salvar a chave privada para '%s': %s",
                session.username,
                e,
            )
            self._audit_keys_fail(session, "falha ao gravar a chave privada no workspace")
            raise FilePermissionError(
                f"Sem privilégios para criar arquivos no workspace: {e}"
            ) from e
        finally:
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    os.remove(tmp_path)

        logger.info("KEYS_GENERATED: Par de chaves gerado para '%s'.", session.username)
        self.audit.record(
            AuditAction.KEYS_GENERATE,
            user_id=session.user_id,
            username=session.username,
            details={"replaced": True} if has_public_key else None,
        )
        return priv_path

    def _set_public_key(self, username: str, public_key: str | None) -> None:
        with self._db() as db:
            db.scalar(select(User).where(User.username == username)).public_key = public_key
            db.commit()

    def _audit_keys_fail(self, session: Session, reason: str) -> None:
        self.audit.record(
            AuditAction.KEYS_GENERATE,
            user_id=session.user_id,
            username=session.username,
            status=AuditStatus.FAIL,
            details={"reason": reason},
        )

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

        absolute_path = abs_path(file_path)
        if os.path.islink(absolute_path):
            # Cifraria o destino do link mas removeria só o link: o texto claro
            # continuaria no lugar real, fora do controle do sistema.
            self._audit_encrypt_fail(session, file_path, target, "origem é um link simbólico")
            raise FilePermissionError(
                "Links simbólicos não podem ser encriptados; informe o caminho do arquivo real."
            )
        if self._is_protected_file(absolute_path):
            # Cifrar (e portanto apagar) a chave privada ou a chave HMAC da
            # auditoria inutilizaria as chaves do sistema e o log já assinado.
            self._audit_encrypt_fail(session, file_path, target, "arquivo de chave do sistema")
            raise FilePermissionError(
                "Arquivos de chave do sistema (private.pem e a chave da auditoria) "
                "não podem ser encriptados."
            )

        try:
            # Só confere o acesso agora: o conteúdo é lido em blocos na cifragem.
            with open(absolute_path, "rb"):
                pass
        except FileNotFoundError as e:
            logger.error("FILE_NOT_FOUND: Arquivo fonte ausente na encriptação: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "arquivo fonte ausente")
            raise CryptoFileNotFoundError(
                f"Arquivo '{file_path}' não encontrado para encriptação."
            ) from e
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler/escrever arquivo: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "falha de permissão ao ler/escrever")
            raise FilePermissionError(f"Sem permissão de acesso ao arquivo: {e}") from e

        file_id = str(uuid.uuid4())
        dek = generate_dek()

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
            raise FilePermissionError(f"Sem permissão de acesso ao arquivo: {e}") from e

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
            # Nunca sobrescreve um .enc existente: isso destruiria o conteúdo
            # cifrado anterior e deixaria os metadados dele órfãos.
            with open(absolute_path, "rb") as source_file, _new_file(final_out) as enc_file:
                enc_file.write(file_id.encode("ascii"))
                original_hash = encrypt_stream(source_file, enc_file, dek)
        except FileExistsError as e:
            logger.error("FILE_EXISTS: Destino cifrado já existe: %s", final_out)
            self._audit_encrypt_fail(session, file_path, target, "arquivo cifrado de destino já existe")
            raise FileAlreadyExistsError(
                f"Já existe um arquivo cifrado em '{final_out}'. "
                "Renomeie o arquivo de origem ou informe outro destino com -o."
            ) from e
        except OSError as e:
            logger.error("ERRO_OS: Falha ao gravar o arquivo cifrado: %s", e)
            self._audit_encrypt_fail(session, file_path, target, "falha de permissão ao ler/escrever")
            raise FilePermissionError(f"Sem permissão ao gravar o arquivo cifrado: {e}") from e

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

        details = {"target": target, "output": final_out}
        # A cifragem já está concluída e registrada: se o original não puder
        # ser apagado (ex.: aberto em outro programa), o sucesso é mantido e o
        # texto claro remanescente é sinalizado em vez de virar uma falha.
        try:
            _secure_delete(absolute_path)
        except OSError as e:
            details["source_removed"] = False
            logger.warning(
                "SOURCE_NOT_REMOVED: '%s' foi encriptado, mas o original em texto claro "
                "não pôde ser apagado (%s). Remova-o manualmente.",
                file_path,
                e,
            )
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
            details=details,
        )
        return final_out

    def _is_protected_file(self, absolute_path: str) -> bool:
        """Chave privada de qualquer workspace ou arquivos de chave/ponta da auditoria."""
        if os.path.basename(absolute_path) == PRIVATE_KEY_NAME:
            return True
        protected = (getattr(self.audit, "_key_file", None), getattr(self.audit, "_head_file", None))
        return any(
            path and os.path.normcase(absolute_path) == os.path.normcase(abs_path(path))
            for path in protected
        )

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
        (04.3). O conteúdo é decifrado em blocos para um temporário 0600 e só
        assume o nome de destino depois de validado: em caso de divergência o
        temporário é sobrescrito e apagado, a operação é abortada com um
        alerta `INTEGRITY_VIOLATION` e nenhum texto claro fica em disco.
        """
        self.sessions.validate(session)
        return self._retrying(
            session,
            encrypted_path,
            AuditAction.FILE_DECRYPT,
            lambda: self._decrypt_once(session, encrypted_path, output_path),
        )

    def _decrypt_once(
        self, session: Session, encrypted_path: str, output_path: str | None
    ) -> str:
        action = AuditAction.FILE_DECRYPT
        file_id = self._read_file_id(session, encrypted_path, action)
        access = self._load_access(session, file_id, encrypted_path, action)
        dek = self._unwrapped_dek(
            session,
            access.wrapped_dek,
            access.wrap_alg,
            encrypted_path,
            action,
            "DEK do registro inválida para este usuário",
        )

        # Reserva o nome de destino (0600, sem sobrescrever) antes de decifrar.
        try:
            if output_path:
                final_out = abs_path(output_path)
                os.makedirs(os.path.dirname(final_out), exist_ok=True)
            else:
                workspace = self._get_user_workspace(session.username)
                final_out = os.path.join(workspace, access.original_name)
            # Texto claro não validado deixado por uma decifragem interrompida
            # (queda do processo) não fica esquecido em disco.
            for orphan in _stale_temps(os.path.dirname(final_out), "plain", STALE_PLAINTEXT_SECONDS):
                logger.warning("ORPHAN_PLAINTEXT: removendo temporário órfão '%s'.", orphan)
                _discard(orphan)
            with _new_file(final_out):
                pass
        except FileExistsError as e:
            logger.error("FILE_EXISTS: Destino da descriptografia já existe: %s", final_out)
            self._audit_decrypt_fail(session, encrypted_path, "arquivo de destino já existe")
            raise FileAlreadyExistsError(
                f"Já existe um arquivo em '{final_out}'. "
                "Mova-o ou informe outro destino com -o."
            ) from e
        except OSError as e:
            return self._decrypt_write_failed(session, encrypted_path, e)

        tmp_path = None
        try:
            with _temp_file(os.path.dirname(final_out), kind="plain") as (tmp_file, tmp_path):
                self._stream_validated(session, file_id, access, dek, encrypted_path, action, tmp_file)
            os.replace(tmp_path, final_out)
            tmp_path = None
        except OSError as e:
            _discard(final_out)
            if tmp_path is not None:
                _discard(tmp_path)
            return self._decrypt_write_failed(session, encrypted_path, e)
        except BaseException:
            # Validação falhou (o temporário já foi descartado): libera o nome.
            _discard(final_out)
            raise

        details = {"output": final_out}
        # O texto claro já foi entregue: falhar ao consumir o .enc não desfaz
        # o sucesso, apenas deixa a cópia cifrada no lugar.
        try:
            os.remove(abs_path(encrypted_path))
        except OSError as e:
            details["enc_removed"] = False
            logger.warning(
                "ENC_NOT_REMOVED: '%s' foi descriptografado, mas o arquivo cifrado "
                "não pôde ser apagado (%s).",
                encrypted_path,
                e,
            )
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
            details=details,
        )
        return final_out

    def _decrypt_write_failed(self, session: Session, encrypted_path: str, error: OSError):
        logger.error("ERRO_OS: Falha ao gravar o arquivo descriptografado: %s", error)
        self._audit_decrypt_fail(session, encrypted_path, "falha de permissão ao gravar o arquivo")
        raise FilePermissionError(f"Sem permissão ao gravar o arquivo: {error}") from error

    def verify_file(self, session: Session, encrypted_path: str) -> VerifyResult:
        """
        Verifica a integridade de um arquivo .enc sem alterá-lo (04.3).

        Mesma validação da descriptografia — tag AES-GCM e hash SHA-256 do
        conteúdo contra o registrado em `files` — mas o conteúdo é apenas
        conferido em blocos: nada é gravado, o .enc não é consumido e o
        resultado fica disponível para o dono conferir quando quiser.
        Divergência registra `INTEGRITY_VIOLATION` e aborta.
        """
        self.sessions.validate(session)
        return self._retrying(
            session,
            encrypted_path,
            AuditAction.FILE_VERIFY,
            lambda: self._verify_once(session, encrypted_path),
        )

    def _verify_once(self, session: Session, encrypted_path: str) -> VerifyResult:
        action = AuditAction.FILE_VERIFY
        file_id = self._read_file_id(session, encrypted_path, action)
        access = self._load_access(session, file_id, encrypted_path, action)
        dek = self._unwrapped_dek(
            session,
            access.wrapped_dek,
            access.wrap_alg,
            encrypted_path,
            action,
            "DEK do registro inválida para este usuário",
        )
        self._stream_validated(session, file_id, access, dek, encrypted_path, action, None)

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
            details={"sha256": access.sha256_hash},
        )
        return VerifyResult(
            file_id=file_id,
            original_name=access.original_name,
            encrypted_path=encrypted_path,
            sha256_hash=access.sha256_hash,
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
        action = AuditAction.FILE_MODIFY
        self.sessions.validate(session)
        file_id = self._read_file_id(session, encrypted_path, action)
        access = self._load_access(session, file_id, encrypted_path, action, require_modify=True)
        dek = self._unwrapped_dek(
            session,
            access.wrapped_dek,
            access.wrap_alg,
            encrypted_path,
            action,
            "DEK do registro inválida para este usuário",
        )

        content_abs = abs_path(content_path)
        try:
            with open(content_abs, "rb"):
                pass
        except OSError as e:
            logger.error("FILE_NOT_FOUND: Arquivo de conteúdo ausente na modificação: %s", e)
            self._audit_fail(
                session, action, encrypted_path, "arquivo de conteúdo ausente ou ilegível"
            )
            raise CryptoFileNotFoundError(
                f"Arquivo de conteúdo '{content_path}' ausente ou ilegível."
            ) from e

        # O conteúdo atual é validado antes da substituição: quem modifica
        # precisa conseguir ler o arquivo, e a adulteração existente é
        # detectada e reportada, não sobreposta (04.3).
        try:
            self._stream_validated(session, file_id, access, dek, encrypted_path, action, None)
        except _ConcurrentChange:
            raise self._conflict(session, encrypted_path, action) from None

        enc_abs = abs_path(encrypted_path)
        try:
            with (
                open(content_abs, "rb") as source_file,
                _temp_file(os.path.dirname(enc_abs)) as (tmp_file, tmp_path),
            ):
                tmp_file.write(file_id.encode("ascii"))
                new_hash = encrypt_stream(source_file, tmp_file, dek)
        except OSError as e:
            logger.error("ERRO_OS: Falha ao gravar o arquivo cifrado modificado: %s", e)
            self._audit_fail(session, action, encrypted_path, "falha ao gravar o arquivo cifrado")
            raise FilePermissionError(f"Sem permissão ao gravar o arquivo cifrado: {e}") from e

        # Substituição atômica e com controle de concorrência: o novo hash é
        # gravado com compare-and-swap da versão e só então o temporário
        # assume o lugar do .enc. Falha em qualquer etapa deixa .enc e hash
        # coerentes, sem gerar um falso INTEGRITY_VIOLATION depois.
        try:
            if not self._bump_version(file_id, access.version, sha256_hash=new_hash):
                raise self._conflict(session, encrypted_path, action)
            try:
                os.replace(tmp_path, enc_abs)
            except OSError as e:
                if not _installed_by_recovery(tmp_path, e):
                    # O .enc antigo segue no lugar: o hash volta a corresponder a ele.
                    self._bump_version(file_id, access.version + 1, sha256_hash=access.sha256_hash)
                    logger.error("ERRO_OS: Falha ao substituir o arquivo cifrado: %s", e)
                    self._audit_fail(session, action, encrypted_path, "falha ao gravar o arquivo cifrado")
                    raise FilePermissionError(
                        f"Não foi possível substituir o arquivo cifrado (está em uso?): {e}"
                    ) from e
            self._finalize_version(file_id, access.version + 1)
        finally:
            _discard(tmp_path)

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
        return enc_abs

    def _bump_version(self, file_id: str, expected_version: int, **values) -> bool:
        """Compare-and-swap: incrementa a versão (e grava `values`) apenas se
        ninguém alterou o arquivo desde a leitura de `expected_version`."""
        with self._db() as db:
            result = db.execute(
                update(File)
                .where(File.file_id == file_id, File.version == expected_version)
                .values(version=File.version + 1, **values)
            )
            db.commit()
            return result.rowcount == 1

    def _finalize_version(self, file_id: str, expected_version: int) -> None:
        """Segundo incremento, depois do `os.replace`: sinaliza a leitores que
        carregaram os metadados entre o commit e a troca do arquivo que eles
        devem repetir a leitura, em vez de acusar adulteração."""
        try:
            self._bump_version(file_id, expected_version)
        except Exception as e:  # o arquivo e os metadados já estão coerentes
            logger.warning("VERSION_FINALIZE: falha ao finalizar a versão de '%s': %s", file_id, e)

    def _file_version(self, file_id: str) -> int | None:
        with self._db() as db:
            return db.scalar(select(File.version).where(File.file_id == file_id))

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

    def _read_file_id(
        self, session: Session, encrypted_path: str, action: AuditAction
    ) -> str:
        """Lê apenas o cabeçalho do .enc e devolve o file_id; o conteúdo é
        processado em blocos depois. Falhas são auditadas com `action`."""
        try:
            with open(abs_path(encrypted_path), "rb") as enc_file:
                header = enc_file.read(ENC_HEADER_SIZE)
        except FileNotFoundError as e:
            logger.error("FILE_NOT_FOUND: Arquivo encriptado ausente: %s", e)
            self._audit_fail(session, action, encrypted_path, "arquivo .enc inexistente")
            raise CryptoFileNotFoundError(
                f"Arquivo encriptado '{encrypted_path}' não encontrado."
            ) from e
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler arquivo encriptado: %s", e)
            self._audit_fail(session, action, encrypted_path, "falha de permissão ao ler arquivo")
            raise FilePermissionError(
                f"Sem permissão para ler o arquivo encriptado: {e}"
            ) from e

        if len(header) < ENC_HEADER_SIZE:
            self._audit_fail(session, action, encrypted_path, "arquivo .enc truncado ou inválido")
            raise InvalidKeyError("O arquivo .enc está truncado ou tem formato inválido.")

        try:
            return str(uuid.UUID(header[:FILE_ID_SIZE].decode("ascii")))
        except (ValueError, UnicodeDecodeError) as e:
            self._audit_fail(session, action, encrypted_path, "formato .enc não reconhecido")
            raise InvalidKeyError(
                "Formato de arquivo .enc não reconhecido (cifrado por uma versão anterior do sistema)."
            ) from e

    def _load_access(
        self,
        session: Session,
        file_id: str,
        encrypted_path: str,
        action: AuditAction,
        require_modify: bool = False,
    ) -> _Access:
        """Metadados do arquivo e concessão do usuário da sessão (03.2/04.1)."""
        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
                self._audit_fail(session, action, encrypted_path, "arquivo sem metadados registrados")
                raise IntegrityError("O arquivo não possui metadados de integridade no sistema.")

            permission = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == file_id,
                    FilePermission.user_id == session.user_id,
                )
            )
            if permission is None:
                self._audit_fail(session, action, encrypted_path, "usuário sem permissão sobre o arquivo")
                raise FilePermissionError("Você não tem permissão de acesso a este arquivo.")
            if require_modify and permission.permission != Permission.MODIFY.value:
                self._audit_fail(
                    session, action, encrypted_path, "usuário sem permissão de modificação sobre o arquivo"
                )
                raise FilePermissionError(
                    "Usuários com permissão de leitura não podem modificar este arquivo."
                )

            return _Access(
                original_name=file_row.original_name,
                sha256_hash=file_row.sha256_hash,
                version=file_row.version,
                permission=permission.permission,
                wrap_alg=permission.wrap_alg,
                wrapped_dek=permission.wrapped_dek,
            )

    def _stream_validated(
        self,
        session: Session,
        file_id: str,
        access: _Access,
        dek: bytes,
        encrypted_path: str,
        action: AuditAction,
        dst: BinaryIO | None,
    ) -> None:
        """Decifra o .enc em blocos para `dst` (ou só confere, com None),
        validando a tag AES-GCM e o hash SHA-256 registrado (04.3)."""
        try:
            with open(abs_path(encrypted_path), "rb") as enc_file:
                enc_file.seek(FILE_ID_SIZE)
                try:
                    digest = decrypt_stream(enc_file, dst, dek)
                except ValueError:
                    failed = "tag AES-GCM inválida: arquivo adulterado ou destinado a outro usuário"
                else:
                    failed = None
        except OSError as e:
            logger.error("ERRO_OS: Falha ao processar o arquivo encriptado: %s", e)
            self._audit_fail(session, action, encrypted_path, "falha de permissão ao ler arquivo")
            raise FilePermissionError(f"Falha ao processar o arquivo encriptado: {e}") from e

        if failed is None and digest != access.sha256_hash:
            failed = "hash SHA-256 do conteúdo diverge do hash original registrado"
        if failed is not None:
            self._on_integrity_failure(
                session,
                file_id,
                access.version,
                encrypted_path,
                action,
                failed,
                recover=lambda: self._recover_interrupted_write(
                    session, file_id, access.sha256_hash, dek, encrypted_path
                ),
            )

    def _on_integrity_failure(
        self,
        session: Session,
        file_id: str,
        version: int,
        encrypted_path: str,
        action: AuditAction,
        reason: str,
        recover: Callable[[], bool] | None = None,
    ) -> None:
        """Distingue adulteração de leitura cruzada com uma alteração legítima.

        Se a versão do arquivo mudou desde a leitura dos metadados (ou muda
        logo em seguida, quando outra operação está entre o commit e a troca
        do arquivo), a leitura é repetida. Se uma gravação interrompida pôde
        ser recuperada (`recover`), também. Caso contrário, é adulteração.
        """
        if self._file_version(file_id) != version:
            raise _ConcurrentChange()
        if recover is not None and recover():
            raise _ConcurrentChange()
        time.sleep(CONCURRENT_SETTLE_SECONDS)
        if self._file_version(file_id) != version:
            raise _ConcurrentChange()
        self._integrity_violation(session, encrypted_path, reason, action)

    def _recover_interrupted_write(
        self,
        session: Session,
        file_id: str,
        sha256_hash: str,
        dek: bytes,
        encrypted_path: str,
    ) -> bool:
        """Conclui um `update`/`revoke` interrompido entre o commit e a troca.

        Nesse caso o banco já descreve o conteúdo novo (hash e DEK) e o .enc
        novo ficou num temporário ao lado do antigo. Só um temporário com o
        mesmo file_id que confira com a DEK e o hash registrados é instalado:
        um arquivo apenas adulterado nunca passa nessa validação.
        """
        enc_abs = abs_path(encrypted_path)
        for candidate in _stale_temps(os.path.dirname(enc_abs), "enc", RECOVERY_MIN_AGE_SECONDS):
            try:
                with open(candidate, "rb") as tmp_file:
                    if tmp_file.read(FILE_ID_SIZE) != file_id.encode("ascii"):
                        continue
                    if decrypt_stream(tmp_file, None, dek) != sha256_hash:
                        continue
                os.replace(candidate, enc_abs)
            except (OSError, ValueError):
                continue
            self._record_recovery(session, encrypted_path, candidate, "gravação do arquivo cifrado")
            return True
        return False

    def _recover_private_key(self, session: Session, encrypted_path: str) -> bool:
        """Conclui um `genkeys --force` interrompido entre o commit e a troca.

        A chave privada nova ficou num temporário do workspace e a pública
        correspondente já está no banco. Só é instalada uma chave que decifre
        com a KEK da sessão e cuja pública seja a registrada.
        """
        with self._db() as db:
            registered = db.scalar(
                select(User.public_key).where(User.username == session.username)
            )
        if not registered:
            return False
        workspace = self._get_user_workspace(session.username)
        for candidate in _stale_temps(workspace, "key", RECOVERY_MIN_AGE_SECONDS):
            try:
                with open(candidate, "rb") as tmp_file:
                    priv = decrypt_with_kek(tmp_file.read(), session.kek)
                if public_key_of(priv).decode("utf-8") != registered:
                    continue
                os.replace(candidate, os.path.join(workspace, PRIVATE_KEY_NAME))
            except (OSError, ValueError):
                continue
            self._record_recovery(session, encrypted_path, candidate, "troca do par de chaves")
            return True
        return False

    def _record_recovery(
        self, session: Session, encrypted_path: str, candidate: str, what: str
    ) -> None:
        logger.warning(
            "RECOVERY: %s interrompida concluída a partir de '%s'.", what, candidate
        )
        self.audit.record(
            AuditAction.RECOVERY,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"recovered": what, "from": os.path.basename(candidate)},
        )

    def _retrying(
        self,
        session: Session,
        encrypted_path: str,
        action: AuditAction,
        operation: Callable[[], T],
    ) -> T:
        """Executa uma leitura, repetindo-a se cruzar com uma alteração simultânea."""
        for _ in range(CONCURRENT_RETRIES):
            try:
                return operation()
            except _ConcurrentChange:
                logger.info(
                    "CONCURRENT_CHANGE: '%s' foi alterado durante a leitura; repetindo.",
                    encrypted_path,
                )
        raise self._conflict(session, encrypted_path, action)

    def _conflict(
        self, session: Session, encrypted_path: str, action: AuditAction
    ) -> ConcurrentModificationError:
        self._audit_fail(session, action, encrypted_path, "alteração simultânea do arquivo")
        return ConcurrentModificationError(
            "O arquivo foi alterado por outra operação ao mesmo tempo. "
            "Nada foi gravado; tente novamente."
        )

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
            # A DEK via RSA não abre com a chave privada do disco: pode ser um
            # `genkeys --force` interrompido; recuperado, tenta de novo (uma vez,
            # pois o temporário deixa de existir).
            if wrap_alg == WrapAlg.RSA.value and self._recover_private_key(session, encrypted_path):
                return self._unwrapped_dek(
                    session, wrapped_dek, wrap_alg, encrypted_path, action, fail_reason
                )
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
        priv_path = os.path.join(workspace, PRIVATE_KEY_NAME)

        if not os.path.exists(priv_path):
            self._audit_fail(session, action, encrypted_path, "chave privada ausente no workspace")
            raise CryptoFileNotFoundError(
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
        o registro. A gravação usa compare-and-swap da versão do arquivo: se
        a DEK foi trocada no meio (revogação simultânea), nada é gravado.
        """
        self.sessions.validate(session)
        action = AuditAction.FILE_SHARE

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

        file_id = self._read_file_id(session, encrypted_path, action)

        with self._db() as db:
            file_row = db.get(File, file_id)
            if file_row is None:
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
            version = file_row.version
            wrap_alg = granter.wrap_alg
            wrapped_dek = granter.wrapped_dek

        dek = self._unwrapped_dek(
            session,
            wrapped_dek,
            wrap_alg,
            encrypted_path,
            action,
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
            bumped = db.execute(
                update(File)
                .where(File.file_id == file_id, File.version == version)
                .values(version=File.version + 1)
            )
            if bumped.rowcount != 1:
                db.rollback()
                raise self._conflict(session, encrypted_path, action)
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
        """
        Revoga o acesso de outro usuário a um arquivo .enc (04.2). Apenas o dono.

        Remover a concessão não basta: quem foi revogado pode ter guardado a
        DEK quando ainda tinha acesso. Por isso a DEK é trocada (rotação): o
        conteúdo é re-cifrado em blocos com uma DEK nova — sem texto claro em
        disco — e ela é reenvolvida para quem continua autorizado (KEK para o
        dono da sessão, RSA para os demais). A DEK antiga deixa de abrir as
        versões seguintes do arquivo.
        """
        self.sessions.validate(session)
        action = AuditAction.FILE_REVOKE
        file_id = self._read_file_id(session, encrypted_path, action)

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

            grants = db.execute(
                select(FilePermission, User)
                .join(User, User.user_id == FilePermission.user_id)
                .where(FilePermission.file_id == file_id)
            ).all()
            if not any(grant.user_id == target_user.user_id for grant, _ in grants):
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "usuário sem acesso concedido ao arquivo"
                )
                raise FilePermissionError(
                    f"O usuário '{target_username}' não possui acesso a este arquivo."
                )

            version = file_row.version
            sha256_hash = file_row.sha256_hash
            # Cópia das concessões para desfazer a revogação se a troca do
            # arquivo falhar depois do commit.
            snapshot = [_grant_snapshot(grant) for grant, _ in grants]
            own = next((grant for grant, _ in grants if grant.user_id == session.user_id), None)
            if own is None:
                self._audit_revoke_fail(
                    session, encrypted_path, target_username, "dono sem concessão registrada"
                )
                raise FilePermissionError("O dono não tem concessão registrada para este arquivo.")
            own_wrap_alg, own_wrapped_dek = own.wrap_alg, own.wrapped_dek
            remaining = [
                (grant.user_id, user.username, user.public_key)
                for grant, user in grants
                if grant.user_id != target_user.user_id
            ]

        old_dek = self._unwrapped_dek(
            session, own_wrapped_dek, own_wrap_alg, encrypted_path, action, "chave do dono não confere"
        )
        new_dek = generate_dek()
        rewrapped = self._rewrap_for(session, new_dek, remaining, encrypted_path, target_username)

        enc_abs = abs_path(encrypted_path)
        failed = None
        try:
            with (
                open(enc_abs, "rb") as enc_file,
                _temp_file(os.path.dirname(enc_abs)) as (tmp_file, tmp_path),
            ):
                enc_file.seek(FILE_ID_SIZE)
                tmp_file.write(file_id.encode("ascii"))
                try:
                    digest = reencrypt_stream(enc_file, tmp_file, old_dek, new_dek)
                except ValueError:
                    failed = "tag AES-GCM inválida: arquivo adulterado ou destinado a outro usuário"
                else:
                    if digest != sha256_hash:
                        failed = "hash SHA-256 do conteúdo diverge do hash original registrado"
                if failed is not None:
                    raise _ValidationFailed()  # descarta o temporário
        except _ValidationFailed:
            pass
        except OSError as e:
            logger.error("ERRO_OS: Falha ao re-cifrar o arquivo na revogação: %s", e)
            self._audit_revoke_fail(
                session, encrypted_path, target_username, "falha ao gravar o arquivo cifrado"
            )
            raise FilePermissionError(f"Sem permissão ao gravar o arquivo cifrado: {e}") from e

        if failed is not None:
            # Fora dos `with`: com o .enc fechado a recuperação consegue trocá-lo
            # (o Windows não substitui arquivos abertos). Recuperada uma gravação
            # interrompida, a revogação é recusada como conflito e pode ser
            # repetida em seguida.
            try:
                self._on_integrity_failure(
                    session, file_id, version, encrypted_path, action, failed,
                    recover=lambda: self._recover_interrupted_write(
                        session, file_id, sha256_hash, old_dek, encrypted_path
                    ),
                )
            except _ConcurrentChange:
                raise self._conflict(session, encrypted_path, action) from None

        try:
            with self._db() as db:
                bumped = db.execute(
                    update(File)
                    .where(File.file_id == file_id, File.version == version)
                    .values(version=File.version + 1)
                )
                if bumped.rowcount != 1:
                    db.rollback()
                    raise self._conflict(session, encrypted_path, action)
                db.execute(
                    delete(FilePermission).where(
                        FilePermission.file_id == file_id,
                        FilePermission.user_id == target_user.user_id,
                    )
                )
                for user_id, wrap_alg, wrapped_dek in rewrapped:
                    db.execute(
                        update(FilePermission)
                        .where(FilePermission.file_id == file_id, FilePermission.user_id == user_id)
                        .values(wrap_alg=wrap_alg, wrapped_dek=wrapped_dek)
                    )
                db.commit()
            try:
                os.replace(tmp_path, enc_abs)
            except OSError as e:
                if not _installed_by_recovery(tmp_path, e):
                    # O .enc antigo (DEK antiga) segue no lugar: desfaz a revogação.
                    self._restore_grants(file_id, snapshot)
                    logger.error("ERRO_OS: Falha ao substituir o arquivo cifrado: %s", e)
                    self._audit_revoke_fail(
                        session, encrypted_path, target_username, "falha ao gravar o arquivo cifrado"
                    )
                    raise FilePermissionError(
                        f"Não foi possível substituir o arquivo cifrado (está em uso?): {e}. "
                        "A revogação foi desfeita."
                    ) from e
            self._finalize_version(file_id, version + 1)
        finally:
            _discard(tmp_path)

        logger.info(
            "FILE_REVOKED: acesso de '%s' a '%s' revogado por '%s' (DEK trocada).",
            target_username,
            encrypted_path,
            session.username,
        )
        self.audit.record(
            AuditAction.FILE_REVOKE,
            user_id=session.user_id,
            username=session.username,
            resource_id=encrypted_path,
            details={"target": target_username, "dek_rotated": True},
        )
        return encrypted_path

    def _rewrap_for(
        self,
        session: Session,
        new_dek: bytes,
        remaining: list[tuple[str, str, str | None]],
        encrypted_path: str,
        target_username: str,
    ) -> list[tuple[str, str, bytes]]:
        """Envolve a DEK nova para cada usuário que continua autorizado."""
        rewrapped = []
        for user_id, username, public_key in remaining:
            if user_id == session.user_id:
                rewrapped.append((user_id, WrapAlg.KEK.value, encrypt_with_kek(new_dek, session.kek)))
                continue
            # A KEK dos demais é desconhecida: a DEK nova vai pela chave pública.
            try:
                if not public_key:
                    raise ValueError("sem chave pública")
                wrapped = wrap_dek_with_public_key(new_dek, public_key.encode("utf-8"))
            except ValueError as e:
                self._audit_revoke_fail(
                    session,
                    encrypted_path,
                    target_username,
                    f"autorizado '{username}' sem chave pública válida para a DEK nova",
                )
                raise InvalidKeyError(
                    f"'{username}' continua autorizado mas não tem chave pública válida para "
                    "receber a DEK nova. Peça que gere chaves (genkeys) ou revogue-o também."
                ) from e
            rewrapped.append((user_id, WrapAlg.RSA.value, wrapped))
        return rewrapped

    def _restore_grants(self, file_id: str, snapshot: list[dict]) -> None:
        """Restaura as concessões (e a DEK antiga) depois de uma revogação desfeita."""
        with self._db() as db:
            db.execute(delete(FilePermission).where(FilePermission.file_id == file_id))
            db.add_all(FilePermission(**grant) for grant in snapshot)
            db.execute(
                update(File).where(File.file_id == file_id).values(version=File.version + 1)
            )
            db.commit()

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
