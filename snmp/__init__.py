from .v1 import SNMPv1

versions = {
    1: SNMPv1,
}

def Manager(*args, version=1, **kwargs):
    try:
        cls = versions[version]
    except KeyError as e:
        msg = "'version' must be one of {}".format(list(versions.keys()))
        raise ValueError(msg) from e

    return cls(*args, **kwargs)
