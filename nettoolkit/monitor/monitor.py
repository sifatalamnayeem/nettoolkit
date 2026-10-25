"""Uptime monitor: runs checks, stores history and alerts on state changes only."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..alerts import ConsoleNotifier, Notifier
from .. import storage
from .checks import CheckResult, Target, run_check

DEFAULT_INTERVAL = 60
DEFAULT_THRESHOLD = 2


def load_config(path: str | Path) -> Tuple[List[Target], Dict[str, Any]]:
    """Read a JSON config. Returns (targets, settings)."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read config '{path}': {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"config '{path}' is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict) or not raw.get("targets"):
        raise ValueError("config must be an object with a non-empty 'targets' list")

    targets = []
    for i, item in enumerate(raw["targets"], start=1):
        try:
            targets.append(Target.from_dict(item))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"target #{i}: {exc}") from exc

    names = [t.name for t in targets]
    if len(set(names)) != len(names):
        raise ValueError("target names must be unique")

    settings = {
        "interval": int(raw.get("interval", DEFAULT_INTERVAL)),
        "fail_threshold": int(raw.get("fail_threshold", DEFAULT_THRESHOLD)),
    }
    if settings["interval"] < 1 or settings["fail_threshold"] < 1:
        raise ValueError("'interval' and 'fail_threshold' must be >= 1")
    return targets, settings


class Monitor:
    """Checks targets and sends an alert only when a target goes DOWN or recovers.

    A target is declared DOWN after `fail_threshold` consecutive failures, so a
    single dropped packet does not wake you up at 3 a.m.
    """

    def __init__(
        self,
        targets: List[Target],
        notifier: Optional[Notifier] = None,
        conn=None,
        fail_threshold: int = DEFAULT_THRESHOLD,
        checker: Callable[[Target], CheckResult] = run_check,
    ):
        self.targets = targets
        self.notifier = notifier or ConsoleNotifier()
        self.conn = conn
        self.fail_threshold = fail_threshold
        self._checker = checker
        self._failures: Dict[str, int] = {t.name: 0 for t in targets}
        self._down: Dict[str, bool] = {t.name: False for t in targets}

    def run_once(self) -> List[CheckResult]:
        results = []
        for target in self.targets:
            result = self._checker(target)
            results.append(result)
            if self.conn is not None:
                storage.save_check(
                    self.conn, storage.now_iso(), result.target, result.kind,
                    result.up, result.latency_ms, result.detail,
                )
            self._update_state(result)
        return results

    def _update_state(self, result: CheckResult) -> None:
        name = result.target
        if result.up:
            was_down = self._down[name]
            self._failures[name] = 0
            self._down[name] = False
            if was_down:
                self.notifier.send(f"🟢 RECOVERED: {name} is back up ({result.detail})")
            return

        self._failures[name] += 1
        if self._failures[name] >= self.fail_threshold and not self._down[name]:
            self._down[name] = True
            self.notifier.send(
                f"🔴 DOWN: {name} ({result.kind}) failed {self._failures[name]} checks in a row: "
                f"{result.detail}"
            )

    def run_forever(
        self,
        interval: int = DEFAULT_INTERVAL,
        on_results: Optional[Callable[[List[CheckResult]], None]] = None,
    ) -> None:
        while True:
            results = self.run_once()
            if on_results:
                on_results(results)
            time.sleep(interval)
