#!/usr/bin/env python3
"""
astro_drive_audit.py

Asztrofotós / képes külső tároló audit script:
- egzakt duplikátumok keresése (méret + SHA256 hash)
- Siril / stacking / cache / temp / collected folders felismerése
- biztonságosabb törlési jelöltek és kézi ellenőrzést igénylő jelöltek listázása
- opcionálisan karantén mappába mozgatás, nem azonnali végleges törlés
- bizonyos mappák kizárása név vagy teljes elérési út alapján
- progress bar és verbose mód
- SQLite állapot/cache adatbázis a gyorsabb újrafuttatáshoz és félbehagyott hash-elés
  folytatásához
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


SCRIPT_VERSION = "2.1"


SAFE_DELETE_NAME_PATTERNS = [
    re.compile(r"^\.ds_store$", re.I),
    re.compile(r"^thumbs\.db$", re.I),
    re.compile(r"^desktop\.ini$", re.I),
    re.compile(r"^\.?_.*\.tmp$", re.I),
    re.compile(r"^\.?_.*\.temp$", re.I),
    re.compile(r"^\.?_.*\.cache$", re.I),
    re.compile(r"^\.?_.*\.log$", re.I),
    re.compile(r"^\.?_.*\.bak$", re.I),
    re.compile(r"^\.?_.*\.old$", re.I),
    re.compile(r"^\.?_.*\.swp$", re.I),
    re.compile(r"^\.?_.*~$", re.I),
    re.compile(r"^\._.*$", re.I),  # macOS AppleDouble metadata files
]

SAFE_DELETE_EXTS = {
    ".tmp", ".temp", ".cache", ".log", ".bak", ".old", ".swp", ".dmp",
}

REVIEW_FILE_PATTERNS = [
    re.compile(r"^pp_", re.I),
    re.compile(r"^r_pp_", re.I),
    re.compile(r"^bkg_pp_", re.I),
    re.compile(r"^rej_", re.I),
    re.compile(r"^registered_", re.I),
    re.compile(r"^drizzle_", re.I),
    re.compile(r"^stacking_", re.I),
    re.compile(r"^seq_", re.I),
    re.compile(r"^master[-_]", re.I),
    re.compile(r"^stacked", re.I),
]

REVIEW_EXTS = {
    ".seq", ".lst",
}

SAFE_DIR_KEYWORDS = {
    "cache", "caches", "tmp", "temp", "preview", "previews",
    "thumbnail", "thumbnails", "__macosx", ".trash", ".trashes",
}

REVIEW_DIR_KEYWORDS = {
    "process", "processing", "registered", "registration",
    "rejected", "drizzle", "stack", "stacking",
    "collected lights", "collected darks", "collected flats", "collected bias",
    "lights collected", "darks collected", "flats collected", "bias collected",
}

KEEP_DIR_KEYWORDS = {
    "final", "finals", "export", "exports", "keep", "keepers", "selected", "best",
}


@dataclass
class FileInfo:
    path: str
    size: int
    mtime_ns: int
    inode: int
    ext: str
    basename: str


@dataclass
class Finding:
    kind: str
    action: str
    risk: str
    path: str
    size_bytes: int
    reason: str
    keep_path: str = ""
    group_id: str = ""


@dataclass
class ExclusionRules:
    excluded_paths: List[Path]
    excluded_dir_names: Set[str]


def eprint(*args: object, **kwargs: object) -> None:
    print(*args, file=sys.stderr, **kwargs)


def human_bytes(num: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{num} B"


def normalize_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def normalized_path_parts(path: Path) -> List[str]:
    return [normalize_name(p) for p in path.parts]


def contains_keyword(path: Path, keywords: Iterable[str], max_parts: Optional[int] = None) -> bool:
    parts = normalized_path_parts(path)
    if max_parts is not None and max_parts > 0:
        parts = parts[-max_parts:]
    wrapped = "/" + "/".join(parts) + "/"
    for kw in keywords:
        kw_norm = normalize_name(kw)
        if kw_norm in parts:
            return True
        if f"/{kw_norm}/" in wrapped:
            return True
    return False


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def is_under_any_path(path: Path, excluded_paths: Sequence[Path]) -> bool:
    for excluded in excluded_paths:
        if path == excluded or is_relative_to(path, excluded):
            return True
    return False


def path_relative_to_root_for_matching(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path.resolve()


def should_exclude_dir(path: Path, rules: ExclusionRules) -> bool:
    if normalize_name(path.name) in rules.excluded_dir_names:
        return True
    return is_under_any_path(path, rules.excluded_paths)


def build_exclusion_rules(
    root: Path,
    report_dir: Path,
    quarantine_root: Path,
    state_db_path: Path,
    exclude_paths_raw: Sequence[str],
    exclude_dir_names_raw: Sequence[str],
) -> ExclusionRules:
    excluded_paths: List[Path] = [
        report_dir.resolve(),
        quarantine_root.resolve(),
        state_db_path.resolve(),
        (root / ".astro_audit_state").resolve(),
        (root / ".astro_audit_reports").resolve(),
        (root / ".astro_quarantine").resolve(),
    ]

    for raw in exclude_paths_raw:
        raw = raw.strip()
        if not raw:
            continue
        raw_path = Path(raw).expanduser()
        if not raw_path.is_absolute():
            raw_path = root / raw_path
        excluded_paths.append(raw_path.resolve())

    excluded_dir_names = {
        normalize_name(name)
        for name in exclude_dir_names_raw
        if name and name.strip()
    }

    unique_paths: List[Path] = []
    seen: Set[str] = set()
    for p in excluded_paths:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        unique_paths.append(p)

    return ExclusionRules(excluded_paths=unique_paths, excluded_dir_names=excluded_dir_names)


class Logger:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def info(self, msg: str) -> None:
        print(msg)

    def verbose_info(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def warn(self, msg: str) -> None:
        eprint(f"FIGYELEM: {msg}")


class ProgressBar:
    def __init__(self, label: str, total: Optional[int] = None, width: int = 28, enabled: bool = True) -> None:
        self.label = label
        self.total = total
        self.width = width
        self.enabled = enabled
        self.current = 0
        self.start = time.monotonic()
        self.last_render = 0.0
        self._printed = False

    def update(self, current: int, extra: str = "") -> None:
        self.current = current
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self.last_render < 0.08 and self.total and current < self.total:
            return
        self.last_render = now
        elapsed = max(0.001, now - self.start)

        if self.total:
            ratio = min(1.0, current / self.total if self.total else 0.0)
            filled = int(self.width * ratio)
            bar = "█" * filled + "·" * (self.width - filled)
            rate = current / elapsed
            eta = (self.total - current) / rate if rate > 0 else 0
            line = f"\r{self.label:<22} [{bar}] {current}/{self.total}  {ratio*100:5.1f}%  ETA {eta:6.1f}s"
        else:
            rate = current / elapsed
            line = f"\r{self.label:<22} {current} elem  {rate:8.1f}/s"

        if extra:
            trimmed = extra
            if len(trimmed) > 90:
                trimmed = "…" + trimmed[-89:]
            line += f"  {trimmed}"

        print(line, end="", flush=True)
        self._printed = True

    def finish(self, extra: str = "") -> None:
        if not self.enabled:
            return
        self.update(self.total if self.total is not None else self.current, extra=extra)
        if self._printed:
            print()


class StateDB:
    def __init__(self, db_path: Path, root: Path) -> None:
        self.db_path = db_path
        self.root = root
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS file_state (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                sha256 TEXT,
                last_seen_run TEXT,
                first_seen_at TEXT,
                last_seen_at TEXT,
                safe_reason TEXT,
                review_reason TEXT,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                root TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                script_version TEXT NOT NULL,
                file_count INTEGER DEFAULT 0,
                safe_count INTEGER DEFAULT 0,
                review_count INTEGER DEFAULT 0,
                duplicate_count INTEGER DEFAULT 0,
                reclaimable_bytes INTEGER DEFAULT 0,
                summary_json TEXT
            );

            CREATE TABLE IF NOT EXISTS run_progress (
                run_id TEXT PRIMARY KEY,
                phase TEXT NOT NULL,
                current_value INTEGER NOT NULL,
                total_value INTEGER,
                updated_at TEXT NOT NULL,
                note TEXT
            );

            CREATE TABLE IF NOT EXISTS file_snapshot (
                run_id TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                sha256 TEXT,
                PRIMARY KEY (run_id, path)
            );

            CREATE INDEX IF NOT EXISTS idx_file_state_last_seen_run ON file_state(last_seen_run);
            CREATE INDEX IF NOT EXISTS idx_file_state_size ON file_state(size);
            CREATE INDEX IF NOT EXISTS idx_snapshot_run ON file_snapshot(run_id);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def start_run(self, run_id: str) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO runs(run_id, root, started_at, finished_at, status, script_version)
            VALUES (?, ?, ?, NULL, 'running', ?)
            """,
            (run_id, str(self.root), datetime.now().isoformat(), SCRIPT_VERSION),
        )
        self.conn.execute(
            """
            INSERT OR REPLACE INTO run_progress(run_id, phase, current_value, total_value, updated_at, note)
            VALUES (?, 'init', 0, NULL, ?, '')
            """,
            (run_id, datetime.now().isoformat()),
        )
        self.conn.commit()

    def update_progress(self, run_id: str, phase: str, current_value: int, total_value: Optional[int], note: str = "") -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO run_progress(run_id, phase, current_value, total_value, updated_at, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, phase, current_value, total_value, datetime.now().isoformat(), note),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, summary: Dict[str, object]) -> None:
        self.conn.execute(
            """
            UPDATE runs
            SET finished_at = ?, status = 'completed',
                file_count = ?, safe_count = ?, review_count = ?, duplicate_count = ?,
                reclaimable_bytes = ?, summary_json = ?
            WHERE run_id = ?
            """,
            (
                datetime.now().isoformat(),
                int(summary["file_count"]),
                int(summary["safe_candidates"]["count"]),
                int(summary["review_candidates"]["count"]),
                int(summary["duplicates"]["count"]),
                int(summary["all_findings"]["reclaimable_bytes"]),
                json.dumps(summary, ensure_ascii=False),
                run_id,
            ),
        )
        self.conn.commit()

    def mark_run_failed(self, run_id: str, note: str) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ?, status = 'failed' WHERE run_id = ?",
            (datetime.now().isoformat(), run_id),
        )
        self.update_progress(run_id, "failed", 0, None, note=note)
        self.conn.commit()

    def get_cached_hash(self, path: str, size: int, mtime_ns: int, inode: int) -> Optional[str]:
        row = self.conn.execute(
            "SELECT sha256, size, mtime_ns, inode FROM file_state WHERE path = ?",
            (path,),
        ).fetchone()
        if not row:
            return None
        if int(row["size"]) == size and int(row["mtime_ns"]) == mtime_ns and int(row["inode"]) == inode:
            return row["sha256"]
        return None

    def upsert_file_state(
        self,
        *,
        run_id: str,
        path: str,
        size: int,
        mtime_ns: int,
        inode: int,
        sha256: Optional[str],
        safe_reason: Optional[str],
        review_reason: Optional[str],
        last_error: Optional[str] = None,
    ) -> None:
        now = datetime.now().isoformat()
        self.conn.execute(
            """
            INSERT INTO file_state(path, size, mtime_ns, inode, sha256, last_seen_run, first_seen_at, last_seen_at, safe_reason, review_reason, last_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                size=excluded.size,
                mtime_ns=excluded.mtime_ns,
                inode=excluded.inode,
                sha256=COALESCE(excluded.sha256, file_state.sha256),
                last_seen_run=excluded.last_seen_run,
                last_seen_at=excluded.last_seen_at,
                safe_reason=excluded.safe_reason,
                review_reason=excluded.review_reason,
                last_error=excluded.last_error
            """,
            (path, size, mtime_ns, inode, sha256, run_id, now, now, safe_reason, review_reason, last_error),
        )

    def save_snapshot_batch(self, run_id: str, batch: Sequence[FileInfo]) -> None:
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO file_snapshot(run_id, path, size, mtime_ns, sha256)
            VALUES (?, ?, ?, ?, COALESCE((SELECT sha256 FROM file_state WHERE path = ?), NULL))
            """,
            [(run_id, fi.path, fi.size, fi.mtime_ns, fi.path) for fi in batch],
        )
        self.conn.commit()

    def update_snapshot_hash(self, run_id: str, path: str, sha256: Optional[str]) -> None:
        self.conn.execute(
            "UPDATE file_snapshot SET sha256 = ? WHERE run_id = ? AND path = ?",
            (sha256, run_id, path),
        )

    def get_last_completed_run_id(self, exclude_run_id: Optional[str] = None) -> Optional[str]:
        if exclude_run_id:
            row = self.conn.execute(
                """
                SELECT run_id FROM runs
                WHERE status = 'completed' AND run_id != ?
                ORDER BY finished_at DESC
                LIMIT 1
                """,
                (exclude_run_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                """
                SELECT run_id FROM runs
                WHERE status = 'completed'
                ORDER BY finished_at DESC
                LIMIT 1
                """
            ).fetchone()
        return row["run_id"] if row else None

    def compare_with_previous_run(self, current_run_id: str) -> Dict[str, object]:
        previous_run_id = self.get_last_completed_run_id(exclude_run_id=current_run_id)
        if not previous_run_id:
            return {
                "previous_run_id": None,
                "added_files": 0,
                "removed_files": 0,
                "changed_files": 0,
                "unchanged_files": 0,
            }

        added = self.conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM file_snapshot cur
            LEFT JOIN file_snapshot prev ON prev.run_id = ? AND prev.path = cur.path
            WHERE cur.run_id = ? AND prev.path IS NULL
            """,
            (previous_run_id, current_run_id),
        ).fetchone()["c"]

        removed = self.conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM file_snapshot prev
            LEFT JOIN file_snapshot cur ON cur.run_id = ? AND cur.path = prev.path
            WHERE prev.run_id = ? AND cur.path IS NULL
            """,
            (current_run_id, previous_run_id),
        ).fetchone()["c"]

        changed = self.conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM file_snapshot cur
            JOIN file_snapshot prev ON prev.run_id = ? AND prev.path = cur.path
            WHERE cur.run_id = ?
              AND (cur.size != prev.size OR cur.mtime_ns != prev.mtime_ns OR COALESCE(cur.sha256, '') != COALESCE(prev.sha256, ''))
            """,
            (previous_run_id, current_run_id),
        ).fetchone()["c"]

        unchanged = self.conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM file_snapshot cur
            JOIN file_snapshot prev ON prev.run_id = ? AND prev.path = cur.path
            WHERE cur.run_id = ?
              AND cur.size = prev.size AND cur.mtime_ns = prev.mtime_ns AND COALESCE(cur.sha256, '') = COALESCE(prev.sha256, '')
            """,
            (previous_run_id, current_run_id),
        ).fetchone()["c"]

        return {
            "previous_run_id": previous_run_id,
            "added_files": int(added),
            "removed_files": int(removed),
            "changed_files": int(changed),
            "unchanged_files": int(unchanged),
        }


def sha256_of_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: Path, rules: ExclusionRules, follow_symlinks: bool = False) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks, topdown=True):
        current = Path(dirpath).resolve()

        if should_exclude_dir(current, rules):
            dirnames[:] = []
            continue

        kept_dirnames = []
        for d in dirnames:
            full = (current / d).resolve()
            if should_exclude_dir(full, rules):
                continue
            kept_dirnames.append(d)
        dirnames[:] = kept_dirnames

        for filename in filenames:
            full = current / filename
            try:
                if not full.is_file():
                    continue
            except OSError:
                continue
            if is_under_any_path(full.resolve(), rules.excluded_paths):
                continue
            yield full.resolve()


def discover_files(root: Path, rules: ExclusionRules, follow_symlinks: bool, progress_enabled: bool, logger: Logger, db: StateDB, run_id: str) -> List[Path]:
    files: List[Path] = []
    bar = ProgressBar("Fájlok listázása", total=None, enabled=progress_enabled)
    last_save = 0

    for idx, path in enumerate(iter_files(root, rules, follow_symlinks=follow_symlinks), start=1):
        files.append(path)
        bar.update(idx, extra=str(path.name))
        if logger.verbose:
            logger.verbose_info(f"[discover] {path}")
        if idx - last_save >= 250:
            db.update_progress(run_id, "discover", idx, None, note=str(path))
            last_save = idx

    db.update_progress(run_id, "discover", len(files), len(files), note="discover_complete")
    bar.finish(extra=f"{len(files)} fájl")
    return files


def is_safe_delete_file(path: Path, root: Path) -> Optional[str]:
    name = path.name
    lower_name = name.lower()
    ext = path.suffix.lower()

    for pattern in SAFE_DELETE_NAME_PATTERNS:
        if pattern.match(lower_name):
            return f"fájlnév alapján tipikus ideiglenes/meta/log fájl: {name}"

    if ext in SAFE_DELETE_EXTS:
        return f"kiterjesztés alapján tipikus ideiglenes/log/back-up fájl: {ext}"

    rel_parent = path_relative_to_root_for_matching(path.parent, root)
    if contains_keyword(rel_parent, SAFE_DIR_KEYWORDS, max_parts=3):
        return f"tipikus cache/tmp/preview mappában található: {path.parent}"

    return None


def is_review_file(path: Path, root: Path) -> Optional[str]:
    ext = path.suffix.lower()
    lower_name = path.name.lower()

    for pattern in REVIEW_FILE_PATTERNS:
        if pattern.match(lower_name):
            return f"Siril/stacking köztes fájlnak tűnik név alapján: {path.name}"

    if ext in REVIEW_EXTS:
        return f"Siril/stacking leíró vagy lista fájlnak tűnik: {ext}"

    rel_parent = path_relative_to_root_for_matching(path.parent, root)
    if contains_keyword(rel_parent, REVIEW_DIR_KEYWORDS, max_parts=3):
        return f"Siril/stacking köztes mappában van: {path.parent}"

    return None


def scan_files(
    root: Path,
    files: Sequence[Path],
    logger: Logger,
    db: StateDB,
    run_id: str,
    progress_enabled: bool,
) -> Tuple[List[FileInfo], List[Finding], List[Finding]]:
    file_infos: List[FileInfo] = []
    safe_candidates: List[Finding] = []
    review_candidates: List[Finding] = []
    bar = ProgressBar("Elemzés", total=len(files), enabled=progress_enabled)
    snapshot_batch: List[FileInfo] = []

    for idx, path in enumerate(files, start=1):
        try:
            stat = path.stat()
        except OSError as exc:
            logger.warn(f"Nem olvasható: {path} ({exc})")
            db.upsert_file_state(
                run_id=run_id,
                path=str(path),
                size=0,
                mtime_ns=0,
                inode=0,
                sha256=None,
                safe_reason=None,
                review_reason=None,
                last_error=str(exc),
            )
            continue

        info = FileInfo(
            path=str(path),
            size=stat.st_size,
            mtime_ns=getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)),
            inode=getattr(stat, "st_ino", 0),
            ext=path.suffix.lower(),
            basename=path.name,
        )
        file_infos.append(info)
        snapshot_batch.append(info)

        safe_reason = is_safe_delete_file(path, root=root)
        review_reason = None if safe_reason else is_review_file(path, root=root)

        if safe_reason:
            safe_candidates.append(Finding(
                kind="safe_candidate",
                action="SAFE_QUARANTINE",
                risk="low",
                path=str(path),
                size_bytes=stat.st_size,
                reason=safe_reason,
            ))
        elif review_reason:
            review_candidates.append(Finding(
                kind="review_candidate",
                action="REVIEW_BEFORE_DELETE",
                risk="medium",
                path=str(path),
                size_bytes=stat.st_size,
                reason=review_reason,
            ))

        db.upsert_file_state(
            run_id=run_id,
            path=info.path,
            size=info.size,
            mtime_ns=info.mtime_ns,
            inode=info.inode,
            sha256=None,
            safe_reason=safe_reason,
            review_reason=review_reason,
        )

        if len(snapshot_batch) >= 500:
            db.save_snapshot_batch(run_id, snapshot_batch)
            snapshot_batch = []

        if idx % 100 == 0:
            db.update_progress(run_id, "scan", idx, len(files), note=path.name)

        if logger.verbose:
            reasons = []
            if safe_reason:
                reasons.append("SAFE")
            if review_reason:
                reasons.append("REVIEW")
            reason_text = ",".join(reasons) if reasons else "OK"
            logger.verbose_info(f"[scan] {idx}/{len(files)} {path} => {reason_text}")

        bar.update(idx, extra=path.name)

    if snapshot_batch:
        db.save_snapshot_batch(run_id, snapshot_batch)
    db.update_progress(run_id, "scan", len(files), len(files), note="scan_complete")
    bar.finish(extra=f"{len(file_infos)} fájl")
    return file_infos, safe_candidates, review_candidates


def file_keep_score(path: Path, root: Path, size: int, mtime_ns: int) -> Tuple[int, int, int, int]:
    score = 0
    rel_path = path_relative_to_root_for_matching(path, root)

    if contains_keyword(rel_path, KEEP_DIR_KEYWORDS, max_parts=4):
        score += 100
    if contains_keyword(rel_path, REVIEW_DIR_KEYWORDS, max_parts=4):
        score -= 40
    if contains_keyword(rel_path, SAFE_DIR_KEYWORDS, max_parts=4):
        score -= 60

    if path.suffix.lower() in {".tif", ".tiff", ".xisf", ".fits", ".fit"}:
        score += 5
    if path.suffix.lower() in {".jpg", ".jpeg", ".png"}:
        score += 2

    depth_bonus = max(0, 20 - len(path.parts))
    score += depth_bonus

    return (score, int(mtime_ns), -len(str(path)), size)


def collect_directory_hints(root: Path, rules: ExclusionRules) -> List[Finding]:
    findings: List[Finding] = []
    review_dir_names = {normalize_name(x) for x in REVIEW_DIR_KEYWORDS}

    for dirpath, dirnames, _ in os.walk(root, topdown=True):
        current = Path(dirpath).resolve()

        if should_exclude_dir(current, rules):
            dirnames[:] = []
            continue

        kept_dirnames = []
        for d in dirnames:
            full = (current / d).resolve()
            if should_exclude_dir(full, rules):
                continue
            kept_dirnames.append(d)
        dirnames[:] = kept_dirnames

        current_norm = normalize_name(current.name)
        if current_norm in review_dir_names:
            total_size = 0
            try:
                for child in current.rglob("*"):
                    if child.is_file() and not is_under_any_path(child.resolve(), rules.excluded_paths):
                        total_size += child.stat().st_size
            except Exception:
                pass

            findings.append(Finding(
                kind="review_directory",
                action="REVIEW_BEFORE_DELETE",
                risk="medium",
                path=str(current),
                size_bytes=total_size,
                reason=f"mappanév alapján tipikus köztes/gyűjtő mappa: {current.name}",
            ))

    return findings


def find_duplicate_findings(
    root: Path,
    file_infos: Sequence[FileInfo],
    min_dup_size_bytes: int,
    logger: Logger,
    db: StateDB,
    run_id: str,
    progress_enabled: bool,
) -> Tuple[List[Finding], Dict[str, int]]:
    by_size: Dict[int, List[FileInfo]] = defaultdict(list)
    for fi in file_infos:
        if fi.size >= min_dup_size_bytes:
            by_size[fi.size].append(fi)

    size_collision_groups = [items for items in by_size.values() if len(items) >= 2]
    hash_candidates = [fi for group in size_collision_groups for fi in group]
    total_hash_jobs = len(hash_candidates)

    dup_findings: List[Finding] = []
    group_index = 0
    cache_hits = 0
    cache_misses = 0
    bar = ProgressBar("Duplikátum hash", total=total_hash_jobs, enabled=progress_enabled)

    hashed_count = 0
    for items in size_collision_groups:
        by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for fi in items:
            path = Path(fi.path)
            digest = db.get_cached_hash(fi.path, fi.size, fi.mtime_ns, fi.inode)
            source = "cache"
            if digest is None:
                source = "hash"
                try:
                    digest = sha256_of_file(path)
                    cache_misses += 1
                except (OSError, PermissionError) as exc:
                    db.upsert_file_state(
                        run_id=run_id,
                        path=fi.path,
                        size=fi.size,
                        mtime_ns=fi.mtime_ns,
                        inode=fi.inode,
                        sha256=None,
                        safe_reason=None,
                        review_reason=None,
                        last_error=str(exc),
                    )
                    logger.warn(f"Hash sikertelen: {path} ({exc})")
                    hashed_count += 1
                    bar.update(hashed_count, extra=path.name)
                    continue
            else:
                cache_hits += 1

            by_hash[digest].append(fi)
            db.upsert_file_state(
                run_id=run_id,
                path=fi.path,
                size=fi.size,
                mtime_ns=fi.mtime_ns,
                inode=fi.inode,
                sha256=digest,
                safe_reason=None,
                review_reason=None,
            )
            db.update_snapshot_hash(run_id, fi.path, digest)

            hashed_count += 1
            if logger.verbose:
                logger.verbose_info(f"[hash:{source}] {hashed_count}/{total_hash_jobs} {path} => {digest[:16]}...")
            if hashed_count % 25 == 0:
                db.update_progress(run_id, "hash", hashed_count, total_hash_jobs, note=path.name)
                db.conn.commit()
            bar.update(hashed_count, extra=path.name)

        for digest, group in by_hash.items():
            if len(group) < 2:
                continue

            group_index += 1
            group_id = f"DUP-{group_index:05d}"
            keep = max(group, key=lambda x: file_keep_score(Path(x.path), root, x.size, x.mtime_ns))
            keep_path = keep.path

            dup_findings.append(Finding(
                kind="exact_duplicate",
                action="KEEP",
                risk="none",
                path=keep.path,
                size_bytes=keep.size,
                reason=f"megtartott referencia példány; hash={digest[:12]}…",
                keep_path=keep_path,
                group_id=group_id,
            ))

            for fi in group:
                if fi.path == keep.path:
                    continue

                p = Path(fi.path)
                risk = "low"
                action = "DUPLICATE_QUARANTINE"
                reason = f"egzakt duplikátum; ugyanaz a hash mint a megtartott példányé: {digest[:12]}…"

                rel_p = path_relative_to_root_for_matching(p, root)
                rel_keep = path_relative_to_root_for_matching(Path(keep_path), root)
                if contains_keyword(rel_p, KEEP_DIR_KEYWORDS, max_parts=4) and not contains_keyword(rel_keep, KEEP_DIR_KEYWORDS, max_parts=4):
                    risk = "medium"
                    action = "REVIEW_BEFORE_DELETE"
                    reason += "; ez is 'keep/final/export' jellegű helyen van"

                dup_findings.append(Finding(
                    kind="exact_duplicate",
                    action=action,
                    risk=risk,
                    path=fi.path,
                    size_bytes=fi.size,
                    reason=reason,
                    keep_path=keep_path,
                    group_id=group_id,
                ))

    db.update_progress(run_id, "hash", hashed_count, total_hash_jobs, note="hash_complete")
    db.conn.commit()
    bar.finish(extra=f"cache hit: {cache_hits}, új hash: {cache_misses}")
    return dup_findings, {"hash_jobs": total_hash_jobs, "cache_hits": cache_hits, "cache_misses": cache_misses}


def summarize_findings(findings: List[Finding]) -> Dict[str, object]:
    total_size = sum(f.size_bytes for f in findings if f.action not in {"KEEP"})
    counts_by_action: Dict[str, int] = defaultdict(int)
    size_by_action: Dict[str, int] = defaultdict(int)

    for f in findings:
        counts_by_action[f.action] += 1
        if f.action != "KEEP":
            size_by_action[f.action] += f.size_bytes

    return {
        "count": len(findings),
        "reclaimable_bytes": total_size,
        "reclaimable_human": human_bytes(total_size),
        "counts_by_action": dict(sorted(counts_by_action.items())),
        "size_by_action_human": {k: human_bytes(v) for k, v in sorted(size_by_action.items())},
    }


def write_csv(path: Path, findings: List[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "kind", "action", "risk", "size_bytes", "size_human",
                "path", "keep_path", "group_id", "reason",
            ],
        )
        writer.writeheader()
        for item in findings:
            row = asdict(item)
            row["size_human"] = human_bytes(item.size_bytes)
            writer.writerow(row)


def write_txt(path: Path, findings: List[Finding], include_actions: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    allowed = set(include_actions)
    with path.open("w", encoding="utf-8") as f:
        for item in findings:
            if item.action in allowed:
                f.write(item.path)
                f.write("\n")


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def move_to_quarantine(src: Path, root: Path, quarantine_root: Path) -> Path:
    relative = src.resolve().relative_to(root.resolve())
    dest = quarantine_root / relative
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        stem = dest.stem
        suffix = dest.suffix
        i = 1
        while True:
            candidate = dest.with_name(f"{stem}__dup{i}{suffix}")
            if not candidate.exists():
                dest = candidate
                break
            i += 1

    shutil.move(str(src), str(dest))
    return dest


def apply_quarantine(
    root: Path,
    quarantine_root: Path,
    findings: List[Finding],
    allowed_actions: Iterable[str],
    logger: Logger,
    progress_enabled: bool,
) -> List[Dict[str, str]]:
    allowed = set(allowed_actions)
    targets = [f for f in findings if f.action in allowed]
    moves: List[Dict[str, str]] = []
    bar = ProgressBar("Karanténba mozgatás", total=len(targets), enabled=progress_enabled)

    for idx, item in enumerate(targets, start=1):
        src = Path(item.path)
        if not src.exists():
            moves.append({"source": str(src), "dest": "", "action": "SKIPPED_MISSING"})
            bar.update(idx, extra=src.name)
            continue

        try:
            dest = move_to_quarantine(src, root, quarantine_root)
            moves.append({"source": str(src), "dest": str(dest), "action": item.action})
            if logger.verbose:
                logger.verbose_info(f"[move] {src} -> {dest}")
        except Exception as exc:
            moves.append({"source": str(src), "dest": "", "action": f"ERROR: {exc}"})
            logger.warn(f"Nem sikerült mozgatni: {src} ({exc})")

        bar.update(idx, extra=src.name)

    bar.finish(extra=f"{len(targets)} elem")
    return moves


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Asztrofotós külső drive audit / takarítási riport.")
    parser.add_argument("root", help="A vizsgálandó gyökérkönyvtár, pl. /Volumes/Archive")
    parser.add_argument(
        "--report-dir",
        help="Riport könyvtár. Alapértelmezés: <root>/.astro_audit_reports/<timestamp>",
        default=None,
    )
    parser.add_argument(
        "--quarantine-dir",
        default=None,
        help="Karantén könyvtár. Alapértelmezés: <root>/.astro_quarantine/<timestamp>",
    )
    parser.add_argument(
        "--state-db",
        default=None,
        help="SQLite állapotfájl. Alapértelmezés: <root>/.astro_audit_state/astro_audit_state.sqlite",
    )
    parser.add_argument(
        "--min-dup-size-mb",
        type=int,
        default=1,
        help="Csak ennél nagyobb fájloknál számol hash-t duplikátumkereséshez. Alapértelmezés: 1 MB",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Symlinkeket is követi (óvatosan használd).",
    )
    parser.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="Kizárandó mappa teljes vagy root-hoz relatív útvonala. Többször megadható.",
    )
    parser.add_argument(
        "--exclude-dir-name",
        action="append",
        default=[],
        help="Kizárandó mappanév bárhol a fa alatt. Többször megadható. Pl: Pictures",
    )
    parser.add_argument(
        "--apply-safe",
        action="store_true",
        help="A SAFE_QUARANTINE jelölteket áthelyezi karanténba.",
    )
    parser.add_argument(
        "--apply-duplicates",
        action="store_true",
        help="A DUPLICATE_QUARANTINE jelölteket áthelyezi karanténba.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Részletes logolás: minden fontosabb lépést és minden hash-elt fájlt kiír.",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Kikapcsolja a progress bart.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = Logger(verbose=args.verbose)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    progress_enabled = not args.no_progress

    root = Path(args.root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        eprint(f"HIBA: a gyökérkönyvtár nem létezik vagy nem könyvtár: {root}")
        return 2

    report_dir = Path(args.report_dir).expanduser().resolve() if args.report_dir else (root / ".astro_audit_reports" / run_id)
    quarantine_root = Path(args.quarantine_dir).expanduser().resolve() if args.quarantine_dir else (root / ".astro_quarantine" / run_id)
    state_db_path = Path(args.state_db).expanduser().resolve() if args.state_db else (root / ".astro_audit_state" / "astro_audit_state.sqlite")

    report_dir.mkdir(parents=True, exist_ok=True)
    state_db_path.parent.mkdir(parents=True, exist_ok=True)

    rules = build_exclusion_rules(
        root=root,
        report_dir=report_dir,
        quarantine_root=quarantine_root,
        state_db_path=state_db_path,
        exclude_paths_raw=args.exclude_path,
        exclude_dir_names_raw=args.exclude_dir_name,
    )

    min_dup_size_bytes = max(0, args.min_dup_size_mb) * 1024 * 1024
    db = StateDB(state_db_path, root)
    db.start_run(run_id)

    try:
        logger.info(f"Vizsgált gyökér: {root}")
        logger.info(f"Riport mappa:    {report_dir}")
        logger.info(f"State DB:        {state_db_path}")
        if args.apply_safe or args.apply_duplicates:
            logger.info(f"Karantén mappa:  {quarantine_root}")
        if rules.excluded_dir_names:
            logger.info("Kizárt mappanevek: " + ", ".join(sorted(rules.excluded_dir_names)))
        if args.exclude_path:
            logger.info("Kizárt útvonalak: " + ", ".join(str(p) for p in args.exclude_path))
        logger.info("")

        logger.info("1/4 Fájlok felderítése...")
        files = discover_files(root, rules, args.follow_symlinks, progress_enabled, logger, db, run_id)
        logger.info(f"Fájlok száma: {len(files)}")
        logger.info("")

        logger.info("2/4 Fájlok elemzése...")
        file_infos, safe_candidates, review_candidates = scan_files(root, files, logger, db, run_id, progress_enabled)
        logger.info(f"SAFE jelöltek: {len(safe_candidates)}")
        logger.info(f"REVIEW jelöltek: {len(review_candidates)}")
        logger.info("")

        logger.info("3/4 Köztes mappák és duplikátumok elemzése...")
        dir_hints = collect_directory_hints(root, rules)
        dup_findings, dup_stats = find_duplicate_findings(
            root=root,
            file_infos=file_infos,
            min_dup_size_bytes=min_dup_size_bytes,
            logger=logger,
            db=db,
            run_id=run_id,
            progress_enabled=progress_enabled,
        )
        logger.info(f"Hash candidate fájlok: {dup_stats['hash_jobs']}")
        logger.info(f"Cache hit: {dup_stats['cache_hits']}")
        logger.info(f"Új hash: {dup_stats['cache_misses']}")
        logger.info("")

        all_findings: List[Finding] = []
        all_findings.extend(safe_candidates)
        all_findings.extend(review_candidates)
        all_findings.extend(dir_hints)
        all_findings.extend(dup_findings)

        compare_summary = db.compare_with_previous_run(run_id)

        summary = {
            "script_version": SCRIPT_VERSION,
            "run_id": run_id,
            "root": str(root),
            "report_dir": str(report_dir),
            "state_db": str(state_db_path),
            "generated_at": datetime.now().isoformat(),
            "file_count": len(file_infos),
            "exclude_dir_names": sorted(rules.excluded_dir_names),
            "exclude_paths": [str(p) for p in rules.excluded_paths],
            "hashing": dup_stats,
            "safe_candidates": summarize_findings(safe_candidates),
            "review_candidates": summarize_findings(review_candidates + dir_hints),
            "duplicates": summarize_findings(dup_findings),
            "all_findings": summarize_findings(all_findings),
            "compare_to_previous_run": compare_summary,
        }

        logger.info("4/4 Riport írása...")
        write_csv(report_dir / "all_findings.csv", all_findings)
        write_csv(report_dir / "safe_candidates.csv", safe_candidates)
        write_csv(report_dir / "review_candidates.csv", review_candidates + dir_hints)
        write_csv(report_dir / "duplicates.csv", dup_findings)
        write_txt(report_dir / "safe_quarantine_paths.txt", all_findings, {"SAFE_QUARANTINE", "DUPLICATE_QUARANTINE"})
        write_txt(report_dir / "review_first_paths.txt", all_findings, {"REVIEW_BEFORE_DELETE"})
        write_json(report_dir / "summary.json", summary)
        write_json(report_dir / "compare_to_previous_run.json", compare_summary)
        db.update_progress(run_id, "report", 1, 1, note="report_complete")

        moves: List[Dict[str, str]] = []
        if args.apply_safe:
            logger.info("")
            logger.info("SAFE jelöltek karanténba mozgatása...")
            moves.extend(apply_quarantine(root, quarantine_root, all_findings, {"SAFE_QUARANTINE"}, logger, progress_enabled))
        if args.apply_duplicates:
            logger.info("")
            logger.info("DUPE jelöltek karanténba mozgatása...")
            moves.extend(apply_quarantine(root, quarantine_root, all_findings, {"DUPLICATE_QUARANTINE"}, logger, progress_enabled))

        if moves:
            write_json(report_dir / "move_log.json", {"moves": moves})

        db.finish_run(run_id, summary)

        print()
        print("=== ÖSSZEFOGLALÓ ===")
        print(f"Összes fájl:                 {summary['file_count']}")
        print(f"Összes talált elem:          {summary['all_findings']['count']}")
        print(f"Visszanyerhető becsült hely: {summary['all_findings']['reclaimable_human']}")
        print(f"SAFE jelöltek:               {summary['safe_candidates']['count']}")
        print(f"REVIEW jelöltek:             {summary['review_candidates']['count']}")
        print(f"Duplikátum bejegyzések:      {summary['duplicates']['count']}")
        print(f"Előző runhoz képest: +{compare_summary['added_files']} új, -{compare_summary['removed_files']} eltűnt, {compare_summary['changed_files']} változott")
        print()
        print("Riport fájlok:")
        print(f"  - {report_dir / 'summary.json'}")
        print(f"  - {report_dir / 'compare_to_previous_run.json'}")
        print(f"  - {report_dir / 'all_findings.csv'}")
        print(f"  - {report_dir / 'safe_candidates.csv'}")
        print(f"  - {report_dir / 'review_candidates.csv'}")
        print(f"  - {report_dir / 'duplicates.csv'}")
        print(f"  - {report_dir / 'safe_quarantine_paths.txt'}")
        print(f"  - {report_dir / 'review_first_paths.txt'}")
        if moves:
            print(f"  - {report_dir / 'move_log.json'}")
        print()
        print("Megjegyzés:")
        print("- A SHA256 cache az SQLite state DB-ben marad, ezért a következő futás gyorsabb lehet.")
        print("- Ha a futás félbeszakad, a már hash-elt és változatlan fájlokat a következő futás nem hash-eli újra.")
        print("- A discovery/scan fázis újraindul, de a drága hash-elés érdemben folytatható.")
        print("- Először mindig riporttal futtasd, csak utána használd az --apply-safe vagy --apply-duplicates opciókat.")
        return 0

    except KeyboardInterrupt:
        db.mark_run_failed(run_id, "Megszakítva felhasználó által")
        eprint("\nMegszakítva. Az eddigi hash/cache állapot el lett mentve az SQLite state DB-be.")
        return 130
    except Exception as exc:
        db.mark_run_failed(run_id, str(exc))
        raise
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
