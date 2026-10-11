import logging

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

    except ValueError as e:
        logger.error(f"Ocorreu um erro: {e}")


if __name__ == "__main__":
    main()
