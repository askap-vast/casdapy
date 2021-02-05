import logging
import sys
from astropy.logger import log as astropy_logger


class StreamHandler(logging.StreamHandler):
    def emit(self, record):
        from astropy.utils.console import color_print
        stream = sys.stdout if record.levelno <= logging.INFO else sys.stderr
        message = self.format(record)
        if record.levelno < logging.INFO:
            print(message, file=stream)
        elif record.levelno < logging.WARNING:
            color_print(message, "green", file=stream)
        elif record.levelno < logging.ERROR:
            color_print(message, "brown", file=stream)
        else:
            color_print(message, "red", file=stream)
        stream.flush()


def _init_log() -> logging.Logger:
    logging_format = "%(asctime)-15s %(levelname)-8s %(message)s [%(origin)s:%(funcName)s]"
    # hijack the astropy logger and set our own format
    logger = astropy_logger
    handler = StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logging_format))
    logger.removeHandler(logger.handlers[0])
    logger.addHandler(handler)
    return logger
