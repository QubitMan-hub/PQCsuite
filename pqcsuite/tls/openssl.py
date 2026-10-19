import sys

from acxelin_core import openssl as _moved

sys.modules[__name__] = _moved  # moved to acxelin-core; this name works until Stage 6
