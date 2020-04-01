import logging
import io

class Logger():

    _instance = None

    def __new__(self):
        if not self._instance:
            self._instance = super(Logger, self).__new__(self)
            self._instance.load()
        return self._instance

    def load(self):

        self.logger = logging.getLogger()

        self.file_handler = logging.FileHandler('totem.log')
        self.stream = io.StringIO()
        self.stream_handler = logging.StreamHandler(self.stream)


        formatter = logging.Formatter('%(asctime)s %(threadName)s -> %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
        self.file_handler.setFormatter(formatter)
        self.stream_handler.setFormatter(formatter)

        self.logger.addHandler(self.file_handler)
        self.logger.addHandler(self.stream_handler)

        self.logger.setLevel(logging.WARNING)

    def write(self, msg):
        self.logger.warning(msg)
        var = self.stream.getvalue()

        self.stream_handler.flush()
        self.file_handler.flush()
        self.stream.truncate(0)
        self.stream.seek(0)

        return var
