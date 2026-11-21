"""The unit tier's database: a throwaway PostgreSQL, started once if a test asks for it.

`database` is a fresh copy of the real schema for one test, with its roles and grants
(`postgres.py` says how). A run in which no test asks for it starts nothing; a run on a
machine without PostgreSQL or its driver skips those tests and says which is missing.
"""

import pytest

import postgres


@pytest.fixture(scope="session")
def cluster():
    try:
        made = postgres.Cluster()
    except postgres.Unavailable as missing:
        pytest.skip(str(missing))
    try:
        made.start()
    except Exception:
        made.stop()
        raise
    yield made
    made.stop()


@pytest.fixture
def database(cluster, tmp_path):
    made = cluster.database(tmp_path / "etc")
    yield made
    made.close()
    cluster.drop(made.name)


# the interface on that database: its scene, its application, a signed-in browser
from admin_db import app_db, browser, ids, made_once  # noqa: E402, F401 - fixtures every interface test shares
from admin_stand_in import (boxes_world, built, check_world, domains_world, driver,  # noqa: E402, F401
                            external_world, journal_world, people_world, shell, signed_out,
                            waiting_world, withheld_pages)

# a mailbox, an archive and a queue for a request that links in batches
from bulk_world import bulk  # noqa: E402, F401
