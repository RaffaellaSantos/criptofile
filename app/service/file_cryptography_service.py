import logging
import os
import shutil
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.core.session import Session, SessionManager
from app.exceptions import (
    IntegrityError,
    InvalidKeyError,
)
from app.exceptions.iam_exceptions import UserNotFoundError
from app.model.user_model import User
from app.utils.cryptography_utils import decrypt, encrypt, generate_priv_pub_key
from app.utils.validator import abs_path

logger = logging.getLogger(__name__)

class FileCryptoService:
    """Serviço responsável pelas operações de criptografia de arquivos e gestão de chaves."""

    def __init__(
        self,
        session_factory: Callable[[], DBSession],
        session_manager: SessionManager,
    ):
        self._db = session_factory
        self.sessions = session_manager

    def _get_user_workspace(self, username: str) -> str:
        """Retorna o caminho do workspace isolado do usuário, criando-o se não existir."""
        path = abs_path(f"./workspace/{username}")
        os.makedirs(path, exist_ok=True)
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
            
            with open(priv_path, "wb") as f_priv:
                f_priv.write(priv)
                
            with self._db() as db:
                user = db.scalar(select(User).where(User.username == session.username))
                if not user:
                    raise UserNotFoundError(f"Usuário '{session.username}' não encontrado no banco.")
                
                user.public_key = pub.decode("utf-8")
                db.commit()

            logger.info("KEYS_GENERATED: Par de chaves gerado para '%s'.", session.username)
            return priv_path

        except OSError as e:
            logger.error("ERRO_OS: Falha ao salvar a chave privada para '%s': %s", session.username, e)
            raise PermissionError(f"Sem privilégios para criar arquivos no workspace: {e}") from e


    def encrypt_file(self, session: Session, file_path: str, target_username: str | None = None, output_path: str | None = None) -> str:
        """
        Encripta um arquivo. Usa a chave pública do target_username (ou do próprio usuário logado).
        """
        self.sessions.validate(session)
        target = target_username if target_username else session.username
        
        with self._db() as db:
            user = db.scalar(select(User).where(User.username == target))
            if not user:
                raise UserNotFoundError(f"Usuário alvo '{target}' não existe no sistema.")
            if not user.public_key:
                raise InvalidKeyError(f"O usuário '{target}' ainda não gerou chaves no sistema.")
            
            pub_key_bytes = user.public_key.encode("utf-8")

        try:
            absolute_path = abs_path(file_path)
            generated_path = encrypt(absolute_path, pub_key_bytes)

            if output_path:
                final_out = abs_path(output_path)
                os.makedirs(os.path.dirname(final_out), exist_ok=True)
            else:
                workspace = self._get_user_workspace(target)
                final_out = os.path.join(workspace, os.path.basename(generated_path))

            if os.path.abspath(generated_path) != os.path.abspath(final_out):
                shutil.move(generated_path, final_out)
            logger.info("FILE_ENCRYPTED: '%s' encriptado para '%s' por '%s'.", file_path, target, session.username)
            return final_out
            
        except FileNotFoundError as e:
            logger.error("FILE_NOT_FOUND: Arquivo fonte ausente na encriptação: %s", e)
            raise FileNotFoundError("FILE_NOT_FOUND: Arquivo fonte ausente na encriptação: %s", e)
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler/escrever arquivo: %s", e)
            raise PermissionError(f"Sem permissão de acesso ao arquivo: {e}") from e


    def decrypt_file(self, session: Session, encrypted_path: str, output_path: str | None = None) -> str:
        """
        Desencripta um arquivo usando a chave privada contida no workspace do usuário logado.
        """
        self.sessions.validate(session)
        
        workspace = self._get_user_workspace(session.username)
        priv_path = os.path.join(workspace, "private.pem")
        
        if not os.path.exists(priv_path):
            raise FileNotFoundError(f"Chave privada não encontrada em '{priv_path}'. Execute 'genkeys' primeiro.")
            
        try:
            with open(priv_path, "rb") as f_key:
                priv_key_bytes = f_key.read()
                
            absolute_path = abs_path(encrypted_path)
            generated_path = decrypt(absolute_path, priv_key_bytes)

            if output_path:
                final_out = abs_path(output_path)
                os.makedirs(os.path.dirname(final_out), exist_ok=True)
            else:
                final_out = os.path.join(workspace, os.path.basename(generated_path))

            if os.path.abspath(generated_path) != os.path.abspath(final_out):
                shutil.move(generated_path, final_out)
            
            logger.info("FILE_DECRYPTED: '%s' aberto com sucesso por '%s'.", encrypted_path, session.username)
            return final_out
            
        except ValueError as e:
            logger.warning("INTEGRITY_FAIL: Tentativa inválida de desencriptar '%s' por '%s'.", encrypted_path, session.username)
            raise IntegrityError("O arquivo foi encriptado para outro usuário ou foi adulterado.") from e
        except OSError as e:
            logger.error("ERRO_OS: Falha de permissão ao ler arquivo encriptado: %s", e)
            raise PermissionError(f"Sem permissão para ler o arquivo ou a chave: {e}") from e