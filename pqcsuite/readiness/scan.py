import sys

from acxelin_readiness import endpoints as _moved

sys.modules[__name__] = _moved  # moved to Acxelin Readiness; this name works until Stage 6
