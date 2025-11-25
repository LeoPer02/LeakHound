import loguru


def setup_logger(log_directory, log_filename="app.log", max_log_size=10 * 1024 * 1024):
    import logging
    import os
    from logging.handlers import RotatingFileHandler
    import colorlog
    from colorama import init

    # Initialize colorama
    init(autoreset=True)

    os.makedirs(log_directory, exist_ok=True)

    log_colors = {
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red'
    }

    formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] [%(module)s.%(funcName)s] [%(threadName)s]%(reset)s \033[1;97m%(message)s\033[0m",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors=log_colors
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # File handler with rotation
    log_filepath = os.path.join(log_directory, log_filename)
    file_handler = RotatingFileHandler(log_filepath, maxBytes=max_log_size, backupCount=5)
    file_handler.setFormatter(formatter)

    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Disable propagation to prevent duplicate logs
    logger.propagate = False

    # Suppress logs from DroidBot classes
    logging.getLogger("UtgNaiveSearchPolicy").setLevel(logging.CRITICAL)
    logging.getLogger("UtgGreedySearchPolicy").setLevel(logging.CRITICAL)


    return logger
