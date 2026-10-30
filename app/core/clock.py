"""The one place the backend reads the wall clock.

Python 3.12 deprecated ``datetime.utcnow()``, but its replacement is
timezone-*aware* while this app has to keep writing naive UTC: the columns are
declared ``DateTime(timezone=True)``, yet SQLite discards the offset and hands
the values back naive, so an aware "now" compared against a stored timestamp
raises TypeError instead of answering. reports.py already carried a
``.replace(tzinfo=None)`` band-aid for exactly that.

So convert once, here: aware arithmetic against a UTC clock, naive result on the
way out. That keeps stored values, comparisons and API payloads byte-identical
while dropping the deprecation.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """UTC now as a naive datetime, matching what the database returns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
