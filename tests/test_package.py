from diskard import __version__
from diskard.cli import main


def test_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_help(capsys) -> None:
    assert main([]) == 0
    captured = capsys.readouterr()
    assert "Lifecycle-aware security testing" in captured.out
