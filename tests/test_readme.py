"""The quickstart output printed in README.md is what the command prints."""

from __future__ import annotations

import re
from pathlib import Path

from mcx_experiment.scenario import main

README = (Path(__file__).parents[1] / "README.md").read_text()


def test_readme_quickstart_output_matches_the_runner(capsys):
    match = re.search(r"<!-- quickstart-output -->\n```text\n(.*?)\n```", README, re.S)
    assert match, "quickstart output block missing"
    assert main(["section-15.4"]) == 0
    assert capsys.readouterr().out.rstrip("\n") == match.group(1)


def test_readme_keeps_the_limits_above_the_quickstart():
    assert README.index("## What this does not show") < README.index("## Quickstart")
