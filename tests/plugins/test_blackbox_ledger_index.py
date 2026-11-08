"""Community Curation C11 — the private ledger's index is sealed (KI-257).

The ledger's index maps each reporter key to the salt of its pseudonym. It is
the only link from a reporter to its entry, and it used to hold reporter keys
in clear. It is now encrypted under a key kept in a third file: a copied index
alone identifies nobody, and the ledger still finds, updates and erases.
"""

from __future__ import annotations

import json
import shutil

import pytest

from plugins.blackbox.community import reputation as rep
from plugins.blackbox.community.reputation import sealed_index

KEY, OTHER = "a1" * 32, "b2" * 32
TODAY = "2026-10-03"


@pytest.fixture
def home(tmp_path):
    """The curator's ledger directory (the test's own tmp_path also holds the suite's Hermes home)."""
    directory = tmp_path / "curate"
    directory.mkdir()
    return directory


def _ledger(directory):
    return rep.ReputationLedger(directory / "reputation.json")


def _filled(directory):
    ledger = _ledger(directory)
    ledger.record(KEY, rep.Outcome("2026-09-10", True), novel=True, first_seen_day="2026-09-01")
    ledger.record(OTHER, rep.Outcome("2026-09-11", False), first_seen_day="2026-09-02")
    return ledger


def test_no_reporter_key_is_readable_in_any_ledger_file(home):
    _filled(home)
    files = sorted(path.name for path in home.iterdir())
    assert files == ["reputation.json", "reputation_index.key", "reputation_salts.json"]
    for path in home.iterdir():
        text = path.read_text(encoding="utf-8")
        assert KEY not in text and OTHER not in text, path.name
        assert oct(path.stat().st_mode & 0o777) == "0o600", path.name
    assert sealed_index.is_sealed((home / "reputation_salts.json").read_text(encoding="utf-8"))


def test_the_ledger_still_finds_updates_and_erases(home):
    _filled(home)
    again = _ledger(home)                                            # a new process
    assert again.keys() == sorted([KEY, OTHER]) and again.standing(KEY).novel_credits == 1
    again.record(KEY, rep.Outcome("2026-09-20", True), novel=True)
    assert _ledger(home).standing(KEY).confirmed == 2 and _ledger(home).standing(OTHER).rejected == 1
    assert again.erase(KEY) and not again.erase(KEY)
    final = _ledger(home)
    assert final.keys() == [OTHER] and final.standing(KEY) == rep.ReporterStanding(key=KEY)
    assert len(json.loads((home / "reputation.json").read_text(encoding="utf-8"))["entries"]) == 1


def test_a_copied_index_alone_identifies_nobody(tmp_path):
    source, thief = tmp_path / "curator", tmp_path / "thief"
    source.mkdir(), thief.mkdir()
    _filled(source)
    shutil.copy(source / "reputation_salts.json", thief / "reputation_salts.json")
    shutil.copy(source / "reputation.json", thief / "reputation.json")      # even together with the entries
    stolen = _ledger(thief)
    assert stolen.keys() == [] and stolen.standing(KEY) == rep.ReporterStanding(key=KEY)
    assert stolen.reputation(KEY, TODAY) == 0.5                             # the prior: nothing is known
    assert sealed_index.open_sealed((thief / "reputation_salts.json").read_text(encoding="utf-8"),
                                    sealed_index.load_or_create_key(thief / "another.key")) is None
    shutil.copy(source / "reputation_index.key", thief / "reputation_index.key")   # all three files open it: the curator's own case
    assert _ledger(thief).keys() == sorted([KEY, OTHER])


def test_an_index_written_before_sealing_is_sealed_the_first_time_it_is_read(home):
    salt = "00" * 16
    (home / "reputation_salts.json").write_text(json.dumps({KEY: salt}), encoding="utf-8")       # the old clear layout
    entry = {"band": "probation", "first_seen_day": "2026-09-01", "confirmed": 3, "rejected": 0, "strikes": 0, "novel_credits": 2,
             "org": "", "sponsor": "", "lockout_until": "", "last_day": "2026-09-30", "outcomes": [{"day": "2026-09-30", "confirmed": True}]}
    (home / "reputation.json").write_text(json.dumps({"entries": {rep.pseudonym(salt, KEY): entry}, "publishers": {}}), encoding="utf-8")
    ledger = _ledger(home)
    assert ledger.standing(KEY).confirmed == 3 and ledger.keys() == [KEY]                  # nothing is lost
    index = (home / "reputation_salts.json").read_text(encoding="utf-8")
    assert KEY not in index and sealed_index.is_sealed(index)                              # and the key is no longer on disk in clear
    assert _ledger(home).standing(KEY).novel_credits == 2


def test_a_lost_or_damaged_index_key_closes_the_ledger_and_is_never_replaced_by_a_clear_index(home):
    _filled(home)
    sealed = (home / "reputation_salts.json").read_text(encoding="utf-8")
    (home / "reputation_index.key").write_text("not a key", encoding="utf-8")
    closed = _ledger(home)
    assert closed.keys() == [] and closed.standing(KEY) == rep.ReporterStanding(key=KEY)
    closed.record(KEY, rep.Outcome(TODAY, True))                         # cannot be saved: the index key is unreadable
    assert (home / "reputation_salts.json").read_text(encoding="utf-8") == sealed      # nothing was written over it
    assert (home / "reputation_index.key").read_text(encoding="utf-8") == "not a key"  # and the key file is left alone
    assert KEY not in "".join(path.read_text(encoding="utf-8") for path in home.iterdir())


def test_a_damaged_index_is_an_empty_index(home):
    _filled(home)
    document = json.loads((home / "reputation_salts.json").read_text(encoding="utf-8"))
    for damaged in ({**document, "sealed": document["sealed"][:-2] + format(int(document["sealed"][-2:], 16) ^ 0xFF, "02x")}, {**document, "sealed": "zz"}, {"v": 2}, {"v": 3, "sealed": "00"}):
        (home / "reputation_salts.json").write_text(json.dumps(damaged), encoding="utf-8")
        assert _ledger(home).keys() == []


def test_sealing_is_authenticated_and_fresh_each_time():
    key = bytes(range(32))
    mapping = {KEY: "00" * 16}
    first, second = sealed_index.seal(mapping, key), sealed_index.seal(mapping, key)
    assert first != second and sealed_index.open_sealed(first, key) == mapping == sealed_index.open_sealed(second, key)
    assert sealed_index.open_sealed(first, bytes(32)) is None and sealed_index.open_sealed(first, None) is None
    assert not sealed_index.is_sealed(json.dumps(mapping)) and not sealed_index.is_sealed("{nope")
