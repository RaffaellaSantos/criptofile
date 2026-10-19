"""Serviço de Auditoria (Requisitos 05.1, 05.2 e proteção do próprio log).

Grava eventos estruturados na tabela `audit_log`, assinando cada registro com
HMAC-SHA256. A assinatura cobre todos os campos do registro; qualquer edição
posterior (de timestamp, usuário, status, etc.) fica detectável por
`verify_integrity()`, atendendo ao requisito de log à prova de adulteração.

A chave do HMAC:
  - vem de `AUDIT_HMAC_KEY` no `.env` (hex), quando definida;
  - caso contrário, é gerada uma única vez e persistida em `.audit_key`
    (chmod 600) no diretório de execução, garantindo que a verificação
    continue possível entre execuções.
"""

import hmac
import json
import logging
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from secrets import token_hex

import socket
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.exceptions.audit_exceptions import AuditError
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus

logger = logging.getLogger(__name__)

DEFAULT_KEY_FILE = ".audit_key"
KEY_BYTES = 32  # HMAC-SHA256


class AuditService:
    def __init__(
        self,
        session_factory: Callable[[], DBSession],
        hmac_key: bytes | None = None,
        key_file: str = DEFAULT_KEY_FILE,
    ):
        self._db = session_factory
        self._key_file = key_file
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
            with open(self._key_file, encoding="ascii") as f:
                return bytes.fromhex(f.read().strip())

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
            with open(self._key_file, encoding="ascii") as f:
                return bytes.fromhex(f.read().strip())
        logger.info("AUDIT_KEY: nova chave de assinatura criada em '%s'.", self._key_file)
        return bytes.fromhex(hex_key)

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
            details=self._serialize_details(details),
            signature_hmac="",  # preenchido a seguir
        )
        event.signature_hmac = self._sign(event)

        with self._db() as db:
            db.add(event)
            # commit() expira os atributos do objeto; guardamos os valores
            # que ainda precisamos antes disso apenas para o log de debug.
            logged_action, logged_status = event.action_type, event.status
            logged_user, logged_resource = username, resource_id
            db.commit()

        logger.debug(
            "AUDIT: %s (%s) user=%s resource=%s",
            logged_action, logged_status, logged_user, logged_resource,
        )

    @staticmethod
    def _serialize_details(details: dict | None) -> str | None:
        if details is None:
            return None
        return json.dumps(details, ensure_ascii=False, sort_keys=True)

    def _sign(self, event: AuditLog) -> str:
        return hmac.new(self._hmac_key, self._canonical(event).encode(), "sha256").hexdigest()

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
        return "|".join(
            [
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
        )

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
        for event in events:
            if not hmac.compare_digest(self._sign(event), event.signature_hmac):
                logger.error(
                    "AUDIT_TAMPER: evento '%s' (%s) foi adulterado.",
                    event.event_id, event.action_type,
                )
                forged.append(event.event_id)
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
        if event.action_type in (AuditAction.SECURITY_ALERT, AuditAction.INTEGRITY_VIOLATION):
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