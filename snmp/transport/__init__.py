import os

if os.name == "posix":
    package = "posix"
else:
    from platform import platform
    raise ImportError("Unsupported platform: \"{}\"".format(platform()))

package = "{}.{}".format(__name__, package)
