from mcx_experiment.redteam import run_catalog


def test_catalog_holds():
    rows = run_catalog()
    assert rows
    assert all(row["ok"] for row in rows), [row["id"] for row in rows if not row["ok"]]
