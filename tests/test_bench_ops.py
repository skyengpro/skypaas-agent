"""Unit tests for the bench CLI wrappers.

We don't run the real ``bench`` binary here. Tests inject a fake
``runner`` that returns a ``CompletedProcess``-shaped object with
canned stdout / stderr / exit code. The contract under test is the
wrapper's parsing, not Frappe's CLI behaviour — Frappe's CLI gets
covered by the real-bench contract test that ships with PR #1B.
"""

from __future__ import annotations

import subprocess
from typing import Sequence

from skypaas_agent.bench_ops import BenchOpResult, format_cmd_for_audit, list_sites


def _make_runner(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a stub ``runner`` returning a CompletedProcess shape."""

    def runner(cmd: Sequence[str]) -> "subprocess.CompletedProcess[str]":
        return subprocess.CompletedProcess(
            args=list(cmd), returncode=returncode, stdout=stdout, stderr=stderr
        )

    return runner


class TestListSitesSuccess:
    def test_parses_one_site(self) -> None:
        runner = _make_runner(stdout="acme-prod.homelab.local\n")
        result, sites = list_sites(runner=runner)
        assert result.ok is True
        assert result.exit_code == 0
        assert sites == ["acme-prod.homelab.local"]

    def test_parses_multiple_sites(self) -> None:
        runner = _make_runner(
            stdout="acme-prod.homelab.local\nacme-staging.homelab.local\nacme-archive.homelab.local\n"
        )
        _, sites = list_sites(runner=runner)
        assert sites == [
            "acme-prod.homelab.local",
            "acme-staging.homelab.local",
            "acme-archive.homelab.local",
        ]

    def test_empty_bench_returns_empty_list(self) -> None:
        runner = _make_runner(stdout="")
        result, sites = list_sites(runner=runner)
        assert result.ok is True
        assert sites == []

    def test_filters_noise_lines(self) -> None:
        """Frappe's older bench versions sometimes prefix the list with
        a banner / footer / blank lines. The wrapper filters to entries
        that look like FQDNs (contain a dot, no spaces, no leading dot)."""
        runner = _make_runner(
            stdout="\n"
            ".hidden-file\n"
            "site_with space\n"
            "no-dot-slug\n"
            "real-site.homelab.local\n"
        )
        _, sites = list_sites(runner=runner)
        assert sites == ["real-site.homelab.local"]

    def test_strips_trailing_whitespace(self) -> None:
        """``bench list-sites`` lines sometimes have trailing CR (on
        Frappe images built on Windows-ish bases). Strip is defensive."""
        runner = _make_runner(stdout="acme-prod.homelab.local   \r\n")
        _, sites = list_sites(runner=runner)
        assert sites == ["acme-prod.homelab.local"]


class TestListSitesFailure:
    def test_non_zero_exit_returns_empty_list_and_not_ok(self) -> None:
        runner = _make_runner(stderr="bench: command not found", returncode=127)
        result, sites = list_sites(runner=runner)
        assert result.ok is False
        assert result.exit_code == 127
        assert result.stderr == "bench: command not found"
        assert sites == []

    def test_failure_preserves_stdout(self) -> None:
        """Even on failure, we capture stdout in case the bench printed
        a partial result before crashing — useful for debugging."""
        runner = _make_runner(stdout="site1.com\n", stderr="exploded", returncode=1)
        result, sites = list_sites(runner=runner)
        assert result.ok is False
        # On failure we return empty sites — partial parse not trusted
        assert sites == []
        # …but the raw stdout is preserved on the result for audit
        assert "site1.com" in result.stdout


class TestBenchOpResultShape:
    def test_result_carries_cmd_and_duration(self) -> None:
        runner = _make_runner(stdout="x.com\n")
        result, _ = list_sites(runner=runner)
        assert result.cmd == ("bench", "list-sites")
        assert isinstance(result.duration_ms, int)
        assert result.duration_ms >= 0  # may be 0 on very fast stubs

    def test_result_is_frozen(self) -> None:
        """BenchOpResult is a dataclass frozen=True so audit-log
        consumers can rely on the value never mutating after capture."""
        result = BenchOpResult(
            ok=True, cmd=("bench", "list-sites"), stdout="", stderr="", exit_code=0, duration_ms=1
        )
        import pytest

        with pytest.raises(Exception):  # FrozenInstanceError
            result.ok = False  # type: ignore[misc]


class TestFormatCmdForAudit:
    def test_simple_cmd(self) -> None:
        assert format_cmd_for_audit(["bench", "list-sites"]) == "bench list-sites"

    def test_quotes_argument_with_space(self) -> None:
        assert "'site with space'" in format_cmd_for_audit(["bench", "use", "site with space"])

    def test_quotes_argument_with_quote(self) -> None:
        # shlex.join handles every shell-special character correctly.
        formatted = format_cmd_for_audit(["bench", "x", "a'b"])
        # Round-trip — the formatted string should reproduce the original cmd
        # when shell-parsed. We don't actually parse here; just confirm
        # the apostrophe got quoted somehow.
        assert "a'b" not in formatted or '"a\'b"' in formatted or "'a'\"'\"'b'" in formatted
