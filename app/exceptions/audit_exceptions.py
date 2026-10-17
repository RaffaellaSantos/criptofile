class AuditError(Exception):
    """Erro base do módulo de auditoria."""


class AuditIntegrityViolationError(AuditError):
    """Um ou mais registros do log de auditoria foram adulterados."""