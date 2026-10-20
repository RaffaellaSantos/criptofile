import logging
import sys

from app.cli.arguments import run
from app.core.logging_config import setup_logging


def main():
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.debug("Iniciando aplicação...")

    try:
        run()
        logger.debug("Aplicação finalizada com sucesso.")
    except KeyboardInterrupt:
        logger.warning("Operação interrompida pelo usuário.")
        # 128 + SIGINT, convenção dos shells para processo interrompido.
        sys.exit(130)

    except ValueError as e:
        logger.error(f"Ocorreu um erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
