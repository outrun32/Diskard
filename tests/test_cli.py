"""Tests for the argparse surface only -- `scan` needs a live target and is
exercised manually (see TEAM_NOTES.md), not here. These pin down exit codes
matching the CLI contract in the dev plan (0/1/2/3) for the parts that
don't need a network."""

import pytest

from diskard.cli import main


def test_no_command_prints_help_and_exits_zero(capsys):
    assert main([]) == 0
    assert "Lifecycle-aware security testing" in capsys.readouterr().out


def test_list_attacks(capsys):
    assert main(["list", "attacks"]) == 0
    assert "cross-user-global-policy-poisoning" in capsys.readouterr().out


def test_list_adapters(capsys):
    assert main(["list", "adapters"]) == 0
    assert "investment-stand" in capsys.readouterr().out


def test_list_without_a_target_is_a_usage_error():
    with pytest.raises(SystemExit) as exc_info:
        main(["list"])
    assert exc_info.value.code == 2


def test_list_rejects_unknown_target():
    with pytest.raises(SystemExit) as exc_info:
        main(["list", "not-a-real-thing"])
    assert exc_info.value.code == 2


def test_scan_help_does_not_touch_the_network():
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "--help"])
    assert exc_info.value.code == 0
