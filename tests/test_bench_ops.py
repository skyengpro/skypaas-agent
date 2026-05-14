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

    def test_redacts_admin_password_two_arg_form(self) -> None:
        formatted = format_cmd_for_audit(
            ["bench", "new-site", "x.com", "--admin-password", "S3kret!"]
        )
        assert "S3kret!" not in formatted
        assert "<REDACTED>" in formatted

    def test_redacts_admin_password_equals_form(self) -> None:
        formatted = format_cmd_for_audit(["bench", "new-site", "x.com", "--admin-password=hunter2"])
        assert "hunter2" not in formatted
        assert "--admin-password=<REDACTED>" in formatted

    def test_redacts_mariadb_root_password(self) -> None:
        formatted = format_cmd_for_audit(
            ["bench", "new-site", "x.com", "--mariadb-root-password", "rootpw"]
        )
        assert "rootpw" not in formatted

    def test_does_not_redact_other_args(self) -> None:
        formatted = format_cmd_for_audit(
            ["bench", "new-site", "acme.example.com", "--admin-email", "ops@example.com"]
        )
        assert "ops@example.com" in formatted
        assert "acme.example.com" in formatted


# ---------- PR #1B mutations ----------
# (extra imports kept here rather than top-of-file for delta clarity;
#  E402 silenced for the same reason)
from skypaas_agent.bench_ops import (  # noqa: E402
    backup_site,
    create_site,
    drop_site,
    restore_site,
)


def _capturing_runner(seen: list[list[str]]):
    """A runner that records each cmd it sees + returns a success process."""

    def runner(cmd):
        seen.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    return runner


class TestCreateSite:
    def test_builds_correct_cmd(self) -> None:
        seen: list[list[str]] = []
        create_site(
            "acme.homelab.local",
            admin_email="ops@example.com",
            admin_password="LongEnoughPw!23",
            runner=_capturing_runner(seen),
        )
        assert seen == [
            [
                "bench",
                "new-site",
                "acme.homelab.local",
                "--admin-email",
                "ops@example.com",
                "--admin-password",
                "LongEnoughPw!23",
                "--install-app",
                "erpnext",
            ]
        ]

    def test_multiple_install_apps(self) -> None:
        seen: list[list[str]] = []
        create_site(
            "x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw!23",
            install_apps=("erpnext", "payments"),
            runner=_capturing_runner(seen),
        )
        assert seen[0].count("--install-app") == 2
        assert "payments" in seen[0]

    def test_passes_mariadb_root_password_when_provided(self) -> None:
        seen: list[list[str]] = []
        create_site(
            "x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw!23",
            mariadb_root_password="rootpw",
            runner=_capturing_runner(seen),
        )
        assert "--mariadb-root-password" in seen[0]
        assert "rootpw" in seen[0]

    def test_propagates_failure(self) -> None:
        runner = _make_runner(stderr="DB connection refused", returncode=1)
        result = create_site(
            "x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw!23",
            runner=runner,
        )
        assert result.ok is False
        assert "DB connection refused" in result.stderr


class TestDropSite:
    def test_default_force_and_no_backup(self) -> None:
        seen: list[list[str]] = []
        drop_site("acme.homelab.local", runner=_capturing_runner(seen))
        assert seen == [["bench", "drop-site", "acme.homelab.local", "--force", "--no-backup"]]

    def test_omits_flags_when_disabled(self) -> None:
        seen: list[list[str]] = []
        drop_site("x.com", force=False, no_backup=False, runner=_capturing_runner(seen))
        assert seen == [["bench", "drop-site", "x.com"]]


class TestBackupSite:
    def test_default_with_files(self) -> None:
        seen: list[list[str]] = []
        backup_site("acme.homelab.local", runner=_capturing_runner(seen))
        assert seen == [["bench", "--site", "acme.homelab.local", "backup", "--with-files"]]

    def test_db_only_when_disabled(self) -> None:
        seen: list[list[str]] = []
        backup_site("x.com", with_files=False, runner=_capturing_runner(seen))
        assert seen == [["bench", "--site", "x.com", "backup"]]


class TestRestoreSite:
    def test_builds_minimal_cmd(self) -> None:
        seen: list[list[str]] = []
        restore_site("acme.homelab.local", "/tmp/backup.sql.gz", runner=_capturing_runner(seen))
        assert seen == [["bench", "--site", "acme.homelab.local", "restore", "/tmp/backup.sql.gz"]]

    def test_includes_file_tarballs_when_provided(self) -> None:
        seen: list[list[str]] = []
        restore_site(
            "x.com",
            "/db.sql.gz",
            public_files_path="/public.tar",
            private_files_path="/private.tar",
            runner=_capturing_runner(seen),
        )
        assert "--with-public-files" in seen[0]
        assert "/public.tar" in seen[0]
        assert "--with-private-files" in seen[0]
        assert "/private.tar" in seen[0]

    def test_includes_admin_password_when_provided(self) -> None:
        seen: list[list[str]] = []
        restore_site(
            "x.com", "/db.sql.gz", admin_password="ResetPw1234!", runner=_capturing_runner(seen)
        )
        assert "--admin-password" in seen[0]
        assert "ResetPw1234!" in seen[0]
