import logging
import sys
from astropy.logger import log as astropy_logger
from http.client import HTTPConnection


class StreamHandler(logging.StreamHandler):
    """StreamHandler that prints colour log records. Essentially the same as
    `astropy.logger.StreamHandler` but retains the logging.StreamHandler format
    compatibility (the former enforces a fixed log message format).
    """

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
    """Initialise the logger, which is `astropy.logger.log` with the default
    StreamHandler replaced with `casdapy.logger.StreamHandler`. Called when the
    `casdapy` module is loaded.

    Returns
    -------
    logging.Logger
    """
    logging_format = (
        "%(asctime)-15s %(levelname)-8s %(message)s [%(origin)s:%(funcName)s]"
    )
    # hijack the astropy logger and set our own format
    logger = astropy_logger
    handler = StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logging_format))
    logger.removeHandler(logger.handlers[0])
    logger.addHandler(handler)
    return logger


def debug_http_on():
    HTTPConnection.debuglevel = 1
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def debug_http_off():
    HTTPConnection.debuglevel = 0
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.WARNING)
    requests_log.propagate = False
