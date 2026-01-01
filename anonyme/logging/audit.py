"""Logger utility for initializing colored and file-based logging."""

import os
import sys
import logging
from typing import Optional
import colorlog
from logging.handlers import RotatingFileHandler


class LoggerManager:
    """Manages logger configuration and initialization."""
    
    _loggers = {}
    
    DEFAULT_LOG_FORMAT = "%(log_color)s[%(levelname)s]%(reset)s - %(message)s"
    DEFAULT_FILE_FORMAT = "[%(levelname)s]: %(asctime)s - %(message)s"
    DEFAULT_LOG_COLORS = {
        "DEBUG": "blue",
        "INFO": "green", 
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "magenta",
    }
    
    @classmethod
    def get_logger(
        cls, 
        name: Optional[str] = None,
        log_level: int = logging.INFO,
        log_dir: str = "logs",
        log_file: str = "running_logs.log",
        max_file_size: int = 10 * 1024 * 1024,
        backup_count: int = 5
    ) -> logging.Logger:
        """
        Get or create a configured logger instance.
        
        Args:
            name: Logger name. If None, uses the calling module's name
            log_level: Logging level (default: INFO)
            log_dir: Directory for log files (default: "logs")
            log_file: Log file name (default: "running_logs.log")
            max_file_size: Maximum size of log file before rotation (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
            
        Returns:
            logging.Logger: Configured logger instance
            
        Raises:
            OSError: If log directory cannot be created
            PermissionError: If insufficient permissions for log file
        """
        if name is None:
            import inspect
            frame = inspect.currentframe().f_back
            name = frame.f_globals.get('__name__', 'unknown')
        
        if name in cls._loggers:
            return cls._loggers[name]
            
        logger = logging.getLogger(name)
        logger.setLevel(log_level)
        logger.propagate = False
        
        try:
            console_handler = cls._create_console_handler(log_level)
            logger.addHandler(console_handler)
            
            file_handler = cls._create_file_handler(
                log_dir, log_file, log_level, max_file_size, backup_count
            )
            logger.addHandler(file_handler)
            
            cls._loggers[name] = logger
            logger.info("Logger initialized successfully.")
            
            return logger
            
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to setup file logging: {e}")
            logger.warning("Continuing with console logging only")
            return logger
    
    @classmethod
    def _create_console_handler(cls, log_level: int) -> colorlog.StreamHandler:
        """Create and configure console handler with colors."""
        console_handler = colorlog.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(
            colorlog.ColoredFormatter(
                fmt=cls.DEFAULT_LOG_FORMAT, 
                log_colors=cls.DEFAULT_LOG_COLORS
            )
        )
        console_handler.setLevel(log_level)
        return console_handler
    
    @classmethod
    def _create_file_handler(
        cls, 
        log_dir: str, 
        log_file: str, 
        log_level: int,
        max_file_size: int,
        backup_count: int
    ) -> RotatingFileHandler:
        """Create and configure rotating file handler."""
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, log_file)
        
        file_handler = RotatingFileHandler(
            filename=log_path,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(
            logging.Formatter(fmt=cls.DEFAULT_FILE_FORMAT)
        )
        file_handler.setLevel(log_level)
        return file_handler
    
    @classmethod
    def reset_loggers(cls):
        """Reset all cached loggers. Useful for testing."""
        for logger in cls._loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
        cls._loggers.clear()


def get_logger(
    name: Optional[str] = None,
    log_level: int = logging.INFO,
    **kwargs
) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name. If None, uses the calling module's name
        log_level: Logging level (default: INFO)
        **kwargs: Additional arguments passed to LoggerManager.get_logger()
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return LoggerManager.get_logger(name=name, log_level=log_level, **kwargs)