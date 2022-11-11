__all__ = [
    "Any",
    "Callable",
    "ClassVar",
    "Generic",
    "Iterator",
    "Literal",
    "NamedTuple",
    "Optional",
    "Tuple",
    "Type",
    "TypeVar",
    "Union",
    "cast",
    "overload",
]

from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Generic
from typing import NamedTuple
from typing import Optional
from typing import TypeVar
from typing import Union
from typing import cast
from typing import overload

import sys
if sys.version_info[:2] >= (3, 9):
    from collections.abc import Iterator
    from builtins import tuple as Tuple
    from builtins import type as Type
else:
    from typing import Iterator
    from typing import Tuple
    from typing import Type

if sys.version_info[:2] >= (3, 8):
    from typing import Literal
else:
    class DummyType:
        def __getitem__(self, key):
            return None

    Literal = DummyType()
