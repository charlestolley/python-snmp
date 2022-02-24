class SNMPException(Exception):
    pass

class SNMPLibraryBug(SNMPException):
    pass

class IncompleteChildClass(SNMPLibraryBug):
    pass

class UnsupportedFeature(SNMPLibraryBug):
    pass

class IncomingMessageError(SNMPException):
    pass
