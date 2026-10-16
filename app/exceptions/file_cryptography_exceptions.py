class FileCryptofileError(Exception):
    """Erro base para operações de arquivo e criptografia no Criptofile."""


class FileNotFoundError(FileCryptofileError):
    """O arquivo especificado ou o arquivo de chave não foi encontrado no sistema."""


class PermissionError(FileCryptofileError):
    """O usuário ou o sistema não possui permissão de leitura/escrita para o arquivo."""


class IntegrityError(FileCryptofileError):
    """Falha de integridade (MAC) na desencriptação. Arquivo adulterado ou chave incorreta."""


class InvalidKeyError(FileCryptofileError):
    """O formato da chave pública ou privada fornecida é inválido ou está corrompido."""