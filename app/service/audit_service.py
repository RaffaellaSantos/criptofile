"""Serviço de Auditoria (Requisitos 05.1, 05.2 e proteção do próprio log).

Grava eventos estruturados na tabela `audit_log`, assinando cada registro com
HMAC-SHA256. A assinatura cobre todos os campos do registro; qualquer edição
posterior (de timestamp, usuário, status, etc.) fica detectável por
`verify_integrity()`, atendendo ao requisito de log à prova de adulteração.

Os eventos formam uma cadeia: cada um assina também a assinatura do anterior
(`prev_hmac`). Apagar um evento do meio do log quebra o elo do seguinte e
também é detectado. A ponta da cadeia é registrada fora do banco (arquivo
`.audit_key.head`, autenticado por HMAC): remover os eventos mais recentes
deixa a ponta registrada apontando para um evento inexistente. Limite
conhecido: restaurar uma cópia antiga desse arquivo junto com o truncamento.

A chave do HMAC:
  - vem de `AUDIT_HMAC_KEY` no `.env` (hex), quando definida;
  - caso contrário, é gerada uma única vez e persistida em `.audit_key`
    (chmod 600) no diretório de execução, garantindo que a verificação
    continue possível entre execuções.
"""

import contextlib
import hmac
import json
import logging
import os
import socket
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from secrets import token_hex

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import aliased

from app.core.config import data_dir, settings
from app.exceptions.audit_exceptions import AuditError
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus

logger = logging.getLogger(__name__)

DEFAULT_KEY_FILE = ".audit_key"
# Marcador devolvido por verify_integrity quando os eventos mais recentes somem.
AUDIT_TRUNCATED = "log-truncado"
KEY_BYTES = 32  # HMAC-SHA256
# Elo do primeiro evento encadeado (não é uma assinatura válida de nenhum evento).
AUDIT_GENESIS = "0" * 64
CHAIN_RETRIES = 5


class AuditService:
    def __init__(
        self,
        session_factory: Callable[[], DBSession],
        hmac_key: bytes | None = None,
        key_file: str | None = None,
        head_file: str | None = None,
    ):
        self._db = session_factory
        self._key_file = key_file or str(data_dir() / DEFAULT_KEY_FILE)
        # Ponta da cadeia guardada fora do banco: remover os eventos mais
        # recentes (que não têm sucessor para acusar a falta) também é detectado.
        self._head_file = head_file or f"{self._key_file}.head"
        self._hmac_key = hmac_key if hmac_key is not None else self._load_key()

    # ------------------------------------------------------------------ #
    # Gestão da chave de assinatura
    # ------------------------------------------------------------------ #
    def _load_key(self) -> bytes:
        """Resolve a chave HMAC: env > arquivo > gera e persiste."""
        env_key = settings.AUDIT_HMAC_KEY
        if env_key:
            try:
                key = bytes.fromhex(env_key)
            except ValueError as e:
                raise AuditError("AUDIT_HMAC_KEY no .env não é um hex válido.") from e
            if len(key) != KEY_BYTES:
                raise AuditError(
                    f"AUDIT_HMAC_KEY deve ter exatamente {KEY_BYTES} bytes em hex."
                )
            return key

        if os.path.exists(self._key_file):
            return self._read_key_file()

        # A chave usada pelo HMAC é SEMPRE a forma decodificada (32 bytes),
        # idêntica ao caminho de leitura acima; gerar e assinar com o texto
        # hex faria o primeiro evento do sistema invalidar na releitura.
        hex_key = token_hex(KEY_BYTES)
        try:
            fd = os.open(self._key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(hex_key)
        except FileExistsError:
            # Outro processo criou o arquivo entre o exists() e o open().
            return self._read_key_file()
        logger.info(
            "AUDIT_KEY: nova chave de assinatura criada em '%s'.", self._key_file
        )
        return bytes.fromhex(hex_key)

    def _read_key_file(self) -> bytes:
        """Lê a chave persistida, rejeitando arquivos corrompidos."""
        try:
            with open(self._key_file, encoding="ascii") as f:
                key = bytes.fromhex(f.read().strip())
        except (UnicodeDecodeError, ValueError) as e:
            raise AuditError(
                f"O arquivo de chave '{self._key_file}' está corrompido (hex inválido)."
            ) from e
        if len(key) != KEY_BYTES:
            raise AuditError(
                f"O arquivo de chave '{self._key_file}' deve conter {KEY_BYTES} bytes em hex."
            )
        return key

    # ------------------------------------------------------------------ #
    # Registro de eventos
    # ------------------------------------------------------------------ #
    def record(
        self,
        action_type: AuditAction | str,
        *,
        user_id: str | None = None,
        username: str | None = None,
        resource_id: str | None = None,
        status: AuditStatus | str = AuditStatus.SUCCESS,
        ip_address: str | None = "127.0.0.1",
        hostname: str | None = None,
        timestamp: datetime | None = None,
        details: dict | None = None,
    ) -> None:
        """Grava um evento assinado no log de auditoria."""
        if hostname is None:
            hostname = socket.gethostname()
        if timestamp is None:
            timestamp = datetime.now(UTC)

        serialized_details = self._serialize_details(details)

        # O evento é encadeado à ponta atual da cadeia. Se outro processo
        # gravar na mesma ponta ao mesmo tempo, a constraint UNIQUE de
        # prev_hmac rejeita um dos dois, que tenta de novo na nova ponta.
        for _ in range(CHAIN_RETRIES):
            event = AuditLog(
                event_id=str(uuid.uuid4()),
                user_id=user_id,
                username=username,
                action_type=str(action_type),
                resource_id=resource_id,
                status=str(status),
                ip_address=ip_address,
                hostname=hostname,
                timestamp=timestamp,
                details=serialized_details,
                signature_hmac="",  # preenchido a seguir
            )
            with self._db() as db:
                event.prev_hmac = self._chain_head(db)
                event.signature_hmac = signature = self._sign(event)
                db.add(event)
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    continue
            self._write_head(signature)
            break
        else:
            raise AuditError(
                "Não foi possível encadear o evento de auditoria (concorrência)."
            )

        logger.debug(
            "AUDIT: %s (%s) user=%s resource=%s",
            action_type,
            status,
            username,
            resource_id,
        )

    def _head_mac(self, signature: str) -> str:
        return hmac.new(
            self._hmac_key, f"head|{signature}".encode(), "sha256"
        ).hexdigest()

    def _write_head(self, signature: str) -> None:
        """Registra a ponta atual da cadeia (troca atômica do arquivo).

        Falha aqui não perde o evento (já gravado no banco): só enfraquece a
        detecção de truncamento, por isso vira aviso.
        """
        registered = self._read_head()
        if registered is not None and not self._head_is_valid(*registered):
            # O alarme de truncamento é persistente: novos eventos não podem
            # sobrescrever a evidência de que a ponta anterior sumiu do banco.
            logger.error(
                "AUDIT_TRUNCATED: a ponta registrada do log não existe mais; o registro "
                "da ponta foi mantido como evidência (veja o relatório de auditoria)."
            )
            return
        tmp_path = None
        try:
            directory = os.path.dirname(os.path.abspath(self._head_file))
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".audit_head-")
            with os.fdopen(fd, "w", encoding="ascii") as head:
                head.write(f"{signature} {self._head_mac(signature)}")
            os.replace(tmp_path, self._head_file)
            tmp_path = None
        except OSError as e:
            logger.warning(
                "AUDIT_HEAD: não foi possível registrar a ponta do log: %s", e
            )
        finally:
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    os.remove(tmp_path)

    def _head_is_valid(self, signature: str, mac: str) -> bool:
        """MAC confere e a assinatura registrada existe no banco."""
        if not hmac.compare_digest(mac, self._head_mac(signature)):
            return False
        with self._db() as db:
            return (
                db.scalar(
                    select(AuditLog.event_id).where(
                        AuditLog.signature_hmac == signature
                    )
                )
                is not None
            )

    def _read_head(self) -> tuple[str, str] | None:
        """(assinatura, mac) da ponta registrada; None se nunca foi registrada."""
        try:
            with open(self._head_file, encoding="ascii") as head:
                parts = head.read().split()
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError):
            return ("", "")
        return (parts[0], parts[1]) if len(parts) == 2 else ("", "")

    @staticmethod
    def _chain_head(db: DBSession) -> str:
        """Assinatura do último evento encadeado (que nenhum outro referencia)."""
        successor = aliased(AuditLog)
        head = db.scalar(
            select(AuditLog.signature_hmac)
            .where(
                AuditLog.prev_hmac.is_not(None),
                ~exists().where(successor.prev_hmac == AuditLog.signature_hmac),
            )
            .order_by(AuditLog.timestamp.desc())
            .limit(1)
        )
        return head or AUDIT_GENESIS

    @staticmethod
    def _serialize_details(details: dict | None) -> str | None:
        if details is None:
            return None
        return json.dumps(details, ensure_ascii=False, sort_keys=True)

    def _sign(self, event: AuditLog) -> str:
        return hmac.new(
            self._hmac_key, self._canonical(event).encode(), "sha256"
        ).hexdigest()

    @staticmethod
    def _canonical(event: AuditLog) -> str:
        """Serialização canônica de todos os campos cobertos pela assinatura.

        O timestamp é normalizado para UTC sem sufixo de fuso: bancos como o
        SQLite devolvem o valor sem timezone e a assinatura precisa conferir
        idêntica na releitura.
        """
        ts = event.timestamp
        if ts.tzinfo is not None:
            ts = ts.astimezone(UTC).replace(tzinfo=None)
        fields = [
            event.event_id,
            ts.isoformat(),
            event.user_id or "",
            event.username or "",
            event.action_type,
            event.resource_id or "",
            event.status,
            event.ip_address or "",
            event.hostname or "",
            event.details or "",
        ]
        # O elo da cadeia também é assinado (registros anteriores ao
        # encadeamento não têm o campo e seguem verificáveis).
        if event.prev_hmac is not None:
            fields.append(event.prev_hmac)
        return "|".join(fields)

    # ------------------------------------------------------------------ #
    # Leitura para o relatório (Requisito 05.3)
    # ------------------------------------------------------------------ #
    def list_events(
        self,
        *,
        username: str | None = None,
        action_type: AuditAction | str | None = None,
    ) -> list[AuditLog]:
        """Retorna os eventos do log, do mais antigo ao mais recente.

        A filtragem é opcional: sem argumentos devolve o relatório completo
        de usuários e alterações registrado até o momento.
        """
        filters = []
        if username:
            filters.append(AuditLog.username == username)
        if action_type:
            filters.append(AuditLog.action_type == str(action_type))

        with self._db() as db:
            stmt = select(AuditLog).order_by(AuditLog.timestamp, AuditLog.event_id)
            if filters:
                stmt = stmt.where(*filters)
            return list(db.scalars(stmt))

    # ------------------------------------------------------------------ #
    # Verificação de integridade do log (append-only / anti-adulteração)
    # ------------------------------------------------------------------ #
    def verify_integrity(self) -> list[str]:
        """Verifica a assinatura HMAC de todos os registros.

        Retorna os event_ids alterados (lista vazia = log íntegro).
        Registros cuja assinatura não confere tiveram pelo menos um campo
        modificado após a gravação.
        """
        forged: list[str] = []
        with self._db() as db:
            events = db.scalars(select(AuditLog).order_by(AuditLog.timestamp)).all()
        signatures = {event.signature_hmac for event in events}
        for event in events:
            if not hmac.compare_digest(self._sign(event), event.signature_hmac):
                logger.error(
                    "AUDIT_TAMPER: evento '%s' (%s) foi adulterado.",
                    event.event_id,
                    event.action_type,
                )
                forged.append(event.event_id)
            elif (
                event.prev_hmac not in (None, AUDIT_GENESIS)
                and event.prev_hmac not in signatures
            ):
                # O elo aponta para um evento que não existe mais: o registro
                # imediatamente anterior a este foi apagado do log.
                logger.error(
                    "AUDIT_GAP: o evento anterior a '%s' (%s) foi removido do log.",
                    event.event_id,
                    event.action_type,
                )
                forged.append(event.event_id)

        registered = self._read_head()
        if registered is not None:
            signature, mac = registered
            if (
                not hmac.compare_digest(mac, self._head_mac(signature))
                or signature not in signatures
            ):
                logger.error(
                    "AUDIT_TRUNCATED: a ponta registrada do log não existe mais no banco: "
                    "os eventos mais recentes foram removidos (ou o registro da ponta foi adulterado)."
                )
                forged.append(AUDIT_TRUNCATED)
        return forged

    # ------------------------------------------------------------------ #
    # Exportação do relatório em JSON e CEF (seção 2.3 da especificação)
    # ------------------------------------------------------------------ #
    CEF_HEADER = "CEF:0|CriptoFile|CriptoFile CLI|1.0"
    # Severidade CEF: violações/alertas são críticos, falhas altas e o
    # restante é informativo.
    CEF_SEVERITY_ALERT = 10
    CEF_SEVERITY_FAIL = 7
    CEF_SEVERITY_INFO = 3

    @staticmethod
    def _epoch_ms(ts: datetime) -> int:
        """Timestamp em milissegundos, formatado para CEF."""
        if ts.tzinfo is None:  # bancos sem timezone retornam valor naive
            ts = ts.replace(tzinfo=UTC)
        return int(ts.astimezone(UTC).timestamp() * 1000)

    def export_json(self, events: list[AuditLog]) -> str:
        """Serializa os eventos como JSON estruturado (lista de objetos)."""
        return json.dumps(
            [
                {
                    "event_id": event.event_id,
                    "timestamp": self._canonical_ts(event),
                    "user_id": event.user_id,
                    "username": event.username,
                    "action_type": event.action_type,
                    "resource_id": event.resource_id,
                    "status": event.status,
                    "ip_address": event.ip_address,
                    "hostname": event.hostname,
                    "details": json.loads(event.details) if event.details else None,
                    "signature_hmac": event.signature_hmac,
                    "prev_hmac": event.prev_hmac,
                }
                for event in events
            ],
            ensure_ascii=False,
            indent=2,
        )

    def export_cef(self, events: list[AuditLog]) -> str:
        """Serializa os eventos no formato CEF (Common Event Format).

        Cada evento vira uma única linha "CEF:0|vendor|produto|versão|
        signatureID|nome|severidade|extensão", com os atributos da
        especificação nos campos de extensão (suser, suid, src, shost, csN).
        """
        return "\n".join(self._cef_line(event) for event in events)

    def _cef_line(self, event: AuditLog) -> str:
        if event.action_type in (
            AuditAction.SECURITY_ALERT,
            AuditAction.INTEGRITY_VIOLATION,
        ):
            severity = self.CEF_SEVERITY_ALERT
        elif event.status == AuditStatus.FAIL:
            severity = self.CEF_SEVERITY_FAIL
        else:
            severity = self.CEF_SEVERITY_INFO

        header = "|".join(
            [self.CEF_HEADER, event.event_id, str(event.action_type), str(severity)]
        )
        extension = " ".join(
            f"{key}={self._cef_escape(value)}"
            for key, value in self._cef_fields(event)
            if value is not None
        )
        return f"{header}|{extension}"

    @staticmethod
    def _canonical_ts(event: AuditLog) -> str:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC).isoformat()

    @staticmethod
    def _cef_fields(event: AuditLog) -> list[tuple[str, object]]:
        return [
            ("start", AuditService._epoch_ms(event.timestamp)),
            ("suser", event.username),
            ("suid", event.user_id),
            ("src", event.ip_address),
            ("shost", event.hostname),
            ("cs1Label", "Resource"),
            ("cs1", event.resource_id),
            ("cs2Label", "Outcome"),
            ("cs2", event.status),
            ("cs3Label", "SignatureHmac"),
            ("cs3", event.signature_hmac),
            ("msg", event.details),
        ]

    @staticmethod
    def _cef_escape(value: object) -> str:
        text = str(value)
        return (
            text.replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
