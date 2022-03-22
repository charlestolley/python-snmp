class SNMPException(Exception):
    pass

class SNMPLibraryBug(AssertionError):
    pass

class IncompleteChildClass(SNMPLibraryBug):
    pass

class UnsupportedFeature(SNMPLibraryBug):
    pass

class IncomingMessageError(SNMPException):
    pass
