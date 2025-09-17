#!/usr/bin/env python3
"""Profile the AEAD example using pip-installed tink.

This script profiles repeated executions of the AEAD example supplied in the
prompt. It relies on the pip-installed ``tink`` distribution rather than the
local sources in this repository. The script performs a warm-up phase, gathers
``cProfile`` statistics over the requested number of iterations, and summarizes
which functions dominate runtime. For functions implemented in native ``tink``
bindings (``_pywrap`` modules), the script attempts to expose the underlying C++
target documented in their docstrings.
"""

from __future__ import annotations

import argparse
import cProfile
import importlib
import os
import pstats
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def _sanitize_sys_path() -> None:
    """Remove the repository root from ``sys.path`` to prefer pip packages."""

    script_path = Path(__file__).resolve()
    repo_root = str(script_path.parents[1])
    sanitized: List[str] = []
    for entry in sys.path:
        if not entry:
            # ``''`` maps to the current working directory which, when running
            # this script from the repository root, would expose the local
            # sources that lack generated proto bindings. Prefer the installed
            # package instead.
            continue
        normalized = entry.rstrip(os.sep)
        if normalized == repo_root:
            continue
        sanitized.append(entry)
    sys.path[:] = sanitized


_sanitize_sys_path()

import tink  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import aead  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import secret_key_access  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position


KEYSET = r"""{
    "key": [{
        "keyData": {
            "keyMaterialType": "SYMMETRIC",
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
        },
        "keyId": 294406504,
        "outputPrefixType": "TINK",
        "status": "ENABLED"
    }],
    "primaryKeyId": 294406504
}"""


def example() -> None:
    """Encrypts and decrypts using a static AES-GCM keyset."""

    aead.register()
    keyset_handle = tink.json_proto_keyset_format.parse(KEYSET, secret_key_access.TOKEN)
    primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(b"msg", b"associated_data")
    primitive.decrypt(ciphertext, b"associated_data")


@dataclass
class ProfileRow:
    """Human-readable statistics for a profiled function."""

    rank: int
    function: str
    ncalls: int
    tottime: float
    cumtime: float
    per_call_cum_ms: float
    native_doc: Optional[str]

    def format(self, width: int) -> str:
        line = f"{self.rank:>4}  {self.function:<{width}}  {self.ncalls:>9}  {self.tottime:>11.6f}  {self.cumtime:>11.6f}  {self.per_call_cum_ms:>14.6f}"
        if self.native_doc:
            return f"{line}\n      ↳ {self.native_doc}"
        return line


@dataclass
class ProfileSummary:
    total_wall_time: float
    iterations: int
    warmup_iterations: int
    top_by_cumulative: List[ProfileRow]
    top_by_self: List[ProfileRow]


def _describe_function(func_identifier: Tuple[str, int, str]) -> str:
    return pstats.func_std_string(func_identifier)


def _resolve_native_doc(func_identifier: Tuple[str, int, str]) -> Optional[str]:
    filename, _, func_name = func_identifier
    path = Path(filename)
    module_path: Optional[str] = None

    if filename == "~":
        descriptor = pstats.func_std_string(func_identifier)
        marker = "tink.cc.pybind"
        if marker in descriptor:
            start = descriptor.find(marker)
            end = descriptor.find("}", start)
            qualified = descriptor[start:end] if end != -1 else descriptor[start:]
            module_path, _, _ = qualified.rpartition(".")
    else:
        module_name = path.stem
        if "pywrap" in module_name:
            module_path = f"tink.{module_name}"

    if not module_path:
        return None

    try:
        module = importlib.import_module(module_path)
    except Exception:  # pragma: no cover - best-effort lookup
        return None

    attr_name = func_name
    if func_name.startswith("<built-in method ") and func_name.endswith(">"):
        qualified = func_name[len("<built-in method ") : -1]
        attr_name = qualified.split(".")[-1]

    candidate = getattr(module, attr_name, None)
    if candidate is None:
        return None
    doc = getattr(candidate, "__doc__", None)
    if not doc:
        return None
    first_line = doc.strip().splitlines()[0]
    return first_line if first_line else None


def _build_rows(
    stats: pstats.Stats,
    sort_key: str,
    top_n: int,
) -> List[ProfileRow]:
    entries: List[Tuple[Tuple[str, int, str], Dict[str, float]]] = []
    for identifier, stat in stats.stats.items():
        ccalls, ncalls, tottime, cumtime, _ = stat
        if ncalls == 0:
            continue
        data = {
            "ncalls": ncalls,
            "tottime": tottime,
            "cumtime": cumtime,
        }
        entries.append((identifier, data))

    entries.sort(key=lambda item: item[1][sort_key], reverse=True)

    width = 0
    rows: List[ProfileRow] = []
    for rank, (identifier, data) in enumerate(entries[:top_n], start=1):
        function_desc = _describe_function(identifier)
        width = max(width, len(function_desc))
        rows.append(
            ProfileRow(
                rank=rank,
                function=function_desc,
                ncalls=int(data["ncalls"]),
                tottime=float(data["tottime"]),
                cumtime=float(data["cumtime"]),
                per_call_cum_ms=(float(data["cumtime"]) / data["ncalls"]) * 1000.0,
                native_doc=_resolve_native_doc(identifier),
            )
        )

    for row in rows:
        row.function = row.function.ljust(width)
    return rows


def profile_example(iterations: int, warmup_iterations: int, top_n: int) -> ProfileSummary:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if warmup_iterations < 0:
        raise ValueError("warmup_iterations cannot be negative")
    if top_n <= 0:
        raise ValueError("top_n must be positive")

    for _ in range(warmup_iterations):
        example()

    profiler = cProfile.Profile()
    start = time.perf_counter()
    profiler.enable()
    for _ in range(iterations):
        example()
    profiler.disable()
    total_wall_time = time.perf_counter() - start

    stats = pstats.Stats(profiler)

    top_by_cumulative = _build_rows(stats, "cumtime", top_n)
    top_by_self = _build_rows(stats, "tottime", top_n)
    return ProfileSummary(
        total_wall_time=total_wall_time,
        iterations=iterations,
        warmup_iterations=warmup_iterations,
        top_by_cumulative=top_by_cumulative,
        top_by_self=top_by_self,
    )


def _print_rows(title: str, rows: Iterable[ProfileRow]) -> None:
    rows = list(rows)
    if not rows:
        print(f"{title}: no data")
        return

    header = f"    {'Rank':>4}  {'Function':<70}  {'Calls':>9}  {'Total (s)':>11}  {'Cum (s)':>11}  {'Cum/Call (ms)':>14}"
    print(title)
    print("    " + "-" * 110)
    width = max(len(row.function) for row in rows + [ProfileRow(0, '', 0, 0.0, 0.0, 0.0, None)])
    for row in rows:
        print("    " + row.format(width))
    print()


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000, help="Number of profiled example iterations.")
    parser.add_argument("--warmup", type=int, default=10, help="Warm-up iterations to run before profiling.")
    parser.add_argument("--top", type=int, default=20, help="Number of entries to show in each ranking.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = profile_example(args.iterations, args.warmup, args.top)

    avg_wall_ms = (summary.total_wall_time / summary.iterations) * 1000.0
    print("AEAD example profiling summary")
    print("===============================")
    print(
        "Iterations: {iterations} (warm-up: {warmup})\nTotal wall-clock time: {wall:.6f}s\nAverage wall time per iteration: {avg:.6f}ms\n".format(
            iterations=summary.iterations,
            warmup=summary.warmup_iterations,
            wall=summary.total_wall_time,
            avg=avg_wall_ms,
        )
    )

    _print_rows("Top functions by cumulative time", summary.top_by_cumulative)
    _print_rows("Top functions by self time", summary.top_by_self)


if __name__ == "__main__":
    main()
