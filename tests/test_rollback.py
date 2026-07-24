"""Tests for src/rollback.py.

Coverage:
  - Archive discovery and ordering          (find_recent_archives)
  - Rollback target selection               (find_previous_archive)
  - Diff file discovery                     (find_latest_diff)
  - Pre-flight config resolution            (build_rollback_configs)
  - Orchestration with mocked Nornir/NAPALM (rollback_devices)

No real network connections are made.  Nornir / NAPALM are fully mocked.
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Put src/ on the path so rollback.py's own sibling imports (utils, etc.) resolve.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import rollback  # noqa: E402  (must come after sys.path insert)
from rollback import (
    _strip_show_run_headers,
    build_rollback_configs,
    find_latest_diff,
    find_previous_archive,
    find_recent_archives,
    rollback_devices,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_cfg(directory: Path, name: str, content: str = "hostname test", mtime_offset: float = 0) -> Path:
    """Write a .cfg file and pin its mtime to now + mtime_offset seconds."""
    f = directory / name
    f.write_text(content, encoding="utf-8")
    t = time.time() + mtime_offset
    os.utime(f, (t, t))
    return f


def _make_diff(directory: Path, name: str, content: str = "+some diff", mtime_offset: float = 0) -> Path:
    f = directory / name
    f.write_text(content, encoding="utf-8")
    t = time.time() + mtime_offset
    os.utime(f, (t, t))
    return f


def _make_mock_nr(host_names: list[str]) -> MagicMock:
    """Return a MagicMock Nornir object whose inventory contains *host_names*."""
    mock_nr = MagicMock()
    mock_nr.inventory.hosts = {h: MagicMock() for h in host_names}
    mock_nr.filter.return_value = mock_nr  # filter returns same mock
    return mock_nr


def _make_run_result(host_name: str, diff_text: str = "", failed: bool = False) -> MagicMock:
    """Return a mock AggregatedResult for a single host."""
    mock_item = MagicMock()
    mock_item.name = "napalm_configure_rollback"
    mock_item.result = diff_text

    mock_multi = MagicMock()
    mock_multi.failed = failed
    mock_multi.__iter__ = MagicMock(return_value=iter([mock_item]))
    if failed:
        mock_multi.exception = RuntimeError("connection refused")

    mock_agg = MagicMock()
    mock_agg.items.return_value = [(host_name, mock_multi)]
    return mock_agg


# ---------------------------------------------------------------------------
# _strip_show_run_headers
# ---------------------------------------------------------------------------

class TestStripShowRunHeaders:
    _REAL_SHOW_RUN_HEADER = (
        "Building configuration...\n"
        "\n"
        "Current configuration : 4025 bytes\n"
        "!\n"
        "! Last configuration change at 23:14:34 UTC Wed Jul 22 2026\n"
        "!\n"
        "version 17.3\n"
        "hostname R1\n"
    )

    def test_strips_building_configuration_line(self):
        result = _strip_show_run_headers(self._REAL_SHOW_RUN_HEADER)
        assert "Building configuration" not in result

    def test_strips_current_configuration_line(self):
        result = _strip_show_run_headers(self._REAL_SHOW_RUN_HEADER)
        assert "Current configuration" not in result

    def test_preserves_valid_config_lines(self):
        result = _strip_show_run_headers(self._REAL_SHOW_RUN_HEADER)
        assert "version 17.3" in result
        assert "hostname R1" in result
        assert "!" in result

    def test_no_headers_is_a_no_op(self):
        config = "version 17.3\nhostname R1\n"
        assert _strip_show_run_headers(config) == config.rstrip("\n")

    def test_stripped_config_fed_into_build_rollback_configs(self, tmp_path, monkeypatch):
        """build_rollback_configs must return stripped config text."""
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(
            d, "R1_old.cfg",
            content="Building configuration...\nCurrent configuration : 10 bytes\nhostname old\n",
            mtime_offset=-60,
        )
        _make_cfg(d, "R1_new.cfg", content="hostname new\n", mtime_offset=0)

        configs, _ = build_rollback_configs(["R1"], hours=24)

        _, config_text = configs["R1"]
        assert "Building configuration" not in config_text
        assert "Current configuration" not in config_text
        assert "hostname old" in config_text


# ---------------------------------------------------------------------------
# find_recent_archives
# ---------------------------------------------------------------------------

class TestFindRecentArchives:
    def test_missing_archive_dir_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        with pytest.raises(FileNotFoundError, match="No archive directory"):
            find_recent_archives("R1")

    def test_empty_archive_dir_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        (tmp_path / "R1").mkdir()
        with pytest.raises(FileNotFoundError, match="No archived configurations"):
            find_recent_archives("R1")

    def test_returns_sorted_newest_first(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        older = _make_cfg(d, "R1_old.cfg", mtime_offset=-60)
        newer = _make_cfg(d, "R1_new.cfg", mtime_offset=0)

        result = find_recent_archives("R1")

        assert len(result) == 2
        assert result[0].name == newer.name
        assert result[1].name == older.name

    def test_excludes_files_beyond_age_cutoff(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_stale.cfg", mtime_offset=-(25 * 3600))  # 25 h ago

        result = find_recent_archives("R1", max_age_hours=24)

        assert result == []

    def test_only_matches_device_prefix(self, tmp_path, monkeypatch):
        """Files for a different device in the same dir must not appear."""
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_a.cfg")
        _make_cfg(d, "R2_b.cfg")  # wrong prefix — should not match R1's glob

        result = find_recent_archives("R1")

        assert all(f.name.startswith("R1_") for f in result)


# ---------------------------------------------------------------------------
# find_previous_archive
# ---------------------------------------------------------------------------

class TestFindPreviousArchive:
    def test_returns_second_most_recent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_first.cfg",  mtime_offset=-20)
        _make_cfg(d, "R1_second.cfg", mtime_offset=-10)
        _make_cfg(d, "R1_newest.cfg", mtime_offset=0)

        result = find_previous_archive("R1")

        assert result.name == "R1_second.cfg"

    def test_raises_with_only_one_archive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_only.cfg")

        with pytest.raises(ValueError, match="at least 2 archives"):
            find_previous_archive("R1")

    def test_raises_with_no_archives(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        (tmp_path / "R1").mkdir()

        with pytest.raises(FileNotFoundError):
            find_previous_archive("R1")

    def test_respects_hours_cutoff(self, tmp_path, monkeypatch):
        """When both archives are outside the age window, ValueError is raised."""
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_a.cfg", mtime_offset=-(25 * 3600))
        _make_cfg(d, "R1_b.cfg", mtime_offset=-(26 * 3600))

        with pytest.raises(ValueError, match="at least 2 archives"):
            find_previous_archive("R1", max_age_hours=24)


# ---------------------------------------------------------------------------
# find_latest_diff
# ---------------------------------------------------------------------------

class TestFindLatestDiff:
    def test_returns_none_when_diff_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "DIFF_ROOT", tmp_path)
        assert find_latest_diff("R1") is None

    def test_returns_none_when_no_diff_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "DIFF_ROOT", tmp_path)
        (tmp_path / "R1").mkdir()
        assert find_latest_diff("R1") is None

    def test_returns_most_recent_diff(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "DIFF_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_diff(d, "R1_old.diff", mtime_offset=-30)
        newer = _make_diff(d, "R1_new.diff", mtime_offset=0)

        result = find_latest_diff("R1")

        assert result is not None
        assert result.name == newer.name

    def test_ignores_non_diff_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "DIFF_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        (d / "R1_notes.txt").write_text("not a diff")
        assert find_latest_diff("R1") is None


# ---------------------------------------------------------------------------
# build_rollback_configs
# ---------------------------------------------------------------------------

class TestBuildRollbackConfigs:
    def test_success_returns_archive_and_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", content="hostname R1-old", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", content="hostname R1-new", mtime_offset=0)

        configs, skipped = build_rollback_configs(["R1"], hours=24)

        assert "R1" in configs
        assert skipped == {}
        archive_path, config_text = configs["R1"]
        assert archive_path.name == "R1_old.cfg"   # index [1] = older file
        assert "R1-old" in config_text

    def test_skips_device_with_only_one_archive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_only.cfg", content="hostname R1")

        configs, skipped = build_rollback_configs(["R1"], hours=24)

        assert configs == {}
        assert "R1" in skipped
        assert "at least 2" in skipped["R1"]

    def test_skips_device_with_no_archive_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)

        configs, skipped = build_rollback_configs(["R99"], hours=24)

        assert configs == {}
        assert "R99" in skipped

    def test_mixed_valid_and_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", mtime_offset=0)
        # R2 has no directory

        configs, skipped = build_rollback_configs(["R1", "R2"], hours=24)

        assert "R1" in configs
        assert "R2" in skipped


# ---------------------------------------------------------------------------
# rollback_devices — Nornir and NAPALM fully mocked
# ---------------------------------------------------------------------------

class TestRollbackDevices:
    def test_unknown_device_raises_value_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        mock_nr = _make_mock_nr(["R1", "R2"])

        with patch("rollback.InitNornir", return_value=mock_nr):
            with pytest.raises(ValueError, match="not found in inventory"):
                rollback_devices(["R99"], dry_run=False, hours=24)

    def test_skips_and_returns_failure_when_no_valid_archive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        mock_nr = _make_mock_nr(["R1"])

        with patch("rollback.InitNornir", return_value=mock_nr):
            successes, failures = rollback_devices(["R1"], dry_run=False, hours=24)

        assert successes == {}
        assert "R1" in failures

    def test_dry_run_passes_dry_run_true_to_nornir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", content="hostname old", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", content="hostname new", mtime_offset=0)

        mock_nr = _make_mock_nr(["R1"])
        mock_nr.run.return_value = _make_run_result("R1", diff_text="-old\n+new")

        with patch("rollback.InitNornir", return_value=mock_nr):
            rollback_devices(["R1"], dry_run=True, hours=24)

        call_kwargs = mock_nr.run.call_args.kwargs
        assert call_kwargs.get("dry_run") is True

    def test_live_rollback_returns_napalm_diff(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", content="hostname old", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", content="hostname new", mtime_offset=0)

        diff_text = "-hostname new\n+hostname old"
        mock_nr = _make_mock_nr(["R1"])
        mock_nr.run.return_value = _make_run_result("R1", diff_text=diff_text)

        with patch("rollback.InitNornir", return_value=mock_nr):
            successes, failures = rollback_devices(["R1"], dry_run=False, hours=24)

        assert "R1" in successes
        assert successes["R1"] == diff_text
        assert failures == {}

    def test_live_rollback_succeeds_with_empty_diff(self, tmp_path, monkeypatch, capsys):
        """A successful rollback with no diff output is still reported as completed.

        NAPALM IOS compare_config() can return an empty string on some IOS-XE
        versions even when configure replace applied changes.  The task not
        failing is the authoritative success signal.
        """
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", content="hostname old", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", content="hostname new", mtime_offset=0)

        mock_nr = _make_mock_nr(["R1"])
        mock_nr.run.return_value = _make_run_result("R1", diff_text="")  # empty diff

        with patch("rollback.InitNornir", return_value=mock_nr):
            successes, failures = rollback_devices(["R1"], dry_run=False, hours=24)

        assert "R1" in successes
        assert failures == {}
        captured = capsys.readouterr()
        assert "[+] Rollback completed" in captured.out
        assert "No change needed" not in captured.out

    def test_failed_connection_goes_to_failures(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", mtime_offset=0)

        mock_nr = _make_mock_nr(["R1"])
        mock_nr.run.return_value = _make_run_result("R1", failed=True)

        with patch("rollback.InitNornir", return_value=mock_nr):
            successes, failures = rollback_devices(["R1"], dry_run=False, hours=24)

        assert "R1" not in successes
        assert "R1" in failures

    def test_filter_excludes_skipped_devices(self, tmp_path, monkeypatch):
        """Only devices with valid archives should be passed to nr.run()."""
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", mtime_offset=0)
        # R2 has no archives

        mock_nr = _make_mock_nr(["R1", "R2"])
        mock_nr.run.return_value = _make_run_result("R1", diff_text="diff")

        with patch("rollback.InitNornir", return_value=mock_nr):
            successes, failures = rollback_devices(["R1", "R2"], dry_run=False, hours=24)

        # filter_func was called (verifies the lambda fix)
        mock_nr.filter.assert_called_once()
        filter_func = mock_nr.filter.call_args.kwargs["filter_func"]

        # Manually test the captured lambda: R1 (in rollback_configs) → True
        r1_mock = MagicMock()
        r1_mock.name = "R1"
        r2_mock = MagicMock()
        r2_mock.name = "R2"
        assert filter_func(r1_mock) is True
        assert filter_func(r2_mock) is False

    def test_rollback_configs_passed_to_task(self, tmp_path, monkeypatch):
        """The archive config text must be forwarded to the Nornir task."""
        monkeypatch.setattr(rollback, "ARCHIVE_ROOT", tmp_path)
        d = tmp_path / "R1"
        d.mkdir()
        _make_cfg(d, "R1_old.cfg", content="hostname rollback-target", mtime_offset=-60)
        _make_cfg(d, "R1_new.cfg", content="hostname current", mtime_offset=0)

        mock_nr = _make_mock_nr(["R1"])
        mock_nr.run.return_value = _make_run_result("R1")

        with patch("rollback.InitNornir", return_value=mock_nr):
            rollback_devices(["R1"], dry_run=False, hours=24)

        call_kwargs = mock_nr.run.call_args.kwargs
        assert "rollback_configs" in call_kwargs
        assert "hostname rollback-target" in call_kwargs["rollback_configs"]["R1"]
