import os
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine

default = 'sqlite:///' + (Path(__file__).resolve().parents[1] / 'sentinelx.sqlite3').as_posix()
url = os.getenv('SENTINELX_DATABASE_URL', default)
engine = create_engine(url)

if context.is_offline_mode():
    raise RuntimeError('Run migrations with an online database connection')

with engine.connect() as conn:
    context.configure(connection=conn)
    with context.begin_transaction():
        context.run_migrations()

