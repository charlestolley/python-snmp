class SecurityLevel:
    def __init__(self, auth=False, priv=False):
        if priv and not auth:
            raise ValueError("Cannot enable privacy without authentication")

        self.auth = bool(auth)
        self.priv = bool(priv)
