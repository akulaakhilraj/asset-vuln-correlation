"""Small, dependency-free version comparison that handles values like '1.0.1f' and '9.3p1'."""
import re


def version_key(v: str):
    """Turn a version string into a comparable tuple.

    '1.1.1k' -> (1, 1, 1, 'k'); '9.3p1' -> (9, 3, 'p', 1). Missing parts compare lower.
    """
    if not v:
        return ()
    parts = re.findall(r"\d+|[a-zA-Z]+", v)
    return tuple(int(p) if p.isdigit() else p.lower() for p in parts)


def _cmp(a, b):
    for x, y in zip(a, b):
        if x == y:
            continue
        if type(x) is type(y):
            return -1 if x < y else 1
        # number vs letter: plain number sorts before a lettered suffix (1.0.1 < 1.0.1f)
        return -1 if isinstance(x, int) else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def in_range(version: str, min_v: str, max_v: str, max_inclusive: bool = True) -> bool:
    """True if min_v <= version <= max_v (or < max_v when max_inclusive is False). Unknown versions return False."""
    k = version_key(version)
    if not k:
        return False
    upper = _cmp(k, version_key(max_v))
    return _cmp(k, version_key(min_v or "0")) >= 0 and (upper <= 0 if max_inclusive else upper < 0)
