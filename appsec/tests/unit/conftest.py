"""Unit-test bootstrap: the SQLite test databases store UUID columns as text.

The models use PostgreSQL's ``UUID`` type, which SQLAlchemy renders as a
column declared ``UUID`` on SQLite. SQLite gives such a column NUMERIC
affinity, so the 32-character hex it stores is turned into a number whenever
it reads as one: an id made of digits and a single ``e``, or of digits
only, comes back as a number (two such ids can even collide), and loading
the row fails inside ``uuid.UUID``. About one random id in a million does
it: a rare failure of whichever test drew one.
``CHAR(32)``, which SQLAlchemy uses for its generic ``Uuid`` on SQLite, has
text affinity and keeps the hex as written. PostgreSQL is not affected.
"""
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles


@compiles(UUID, "sqlite")
def _uuid_as_text_on_sqlite(type_, compiler, **kw):
    return "CHAR(32)"
