from anonyme.analyze import analyze
from anonyme.logging.audit import get_logger

logger = get_logger(__name__)

if __name__ == "__main__":
    logger.info("Starting application...")

    analyze("milosz.zawolik@gmail.com", [])