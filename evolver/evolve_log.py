import logging
import logging.config

def GetLogger():
    return logging.getLogger('extensive')

class Logger(object):

    def __init__(self, name, rotatinglogfile):
        self.name = name
        LOG_SETTINGS = {
            'version': 1,
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': 'INFO',
                    'formatter': 'simple',
                    'stream': 'ext://sys.stdout',
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'DEBUG',
                    'formatter': 'detailed',
                    'filename': rotatinglogfile,
                    'mode': 'w',
                    'maxBytes': 10485760,
                    'backupCount': 5,
                },
            },
            'formatters': {
                'simple': {
                    'format': '%(message)s',
                },
                'detailed': {
                    'format': '%(asctime)s %(module)-17s line:%(lineno)-4d ' \
                        '%(levelname)-8s %(message)s',
                },
                'email': {
                    'format': 'Timestamp: %(asctime)s\nModule: %(module)s\n' \
                    'Line: %(lineno)d\nMessage: %(message)s',
                },
            },
            'loggers': {
                'basic': {
                    'level':'INFO',
                    'handlers': ['console',]
                    },
                'extensive': {
                    'level':'DEBUG',
                    'handlers': ['file','console']
                    },
            }
        }
        logging.config.dictConfig(LOG_SETTINGS)
