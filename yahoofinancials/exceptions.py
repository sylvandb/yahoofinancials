# Custom Exception class to handle custom error
class ManagedException(Exception):
    data = None

class ParseException(ManagedException):
    pass

class URLOpenException(ManagedException):
    pass

class DecryptException(ManagedException):
    pass
