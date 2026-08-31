"""Report a training run's live progress to a running ``synapsed`` over HTTP.

The Go daemon does not and will not launch training (PROJECT.md §5.4): a run
registers itself here, then POSTs one progress dict per epoch and a terminal
``{"event": "done"}`` dict; on an exception it POSTs ``/fail``.  The daemon
mirrors that state so the SPA can poll it (PROJECT.md §19.8; ADR 0019).

Every network operation is best-effort.  A dashboard outage must never lose a
model, so a failure is logged through the caller's sink and swallowed — training
continues regardless.  stdlib + numpy only: this uses ``urllib.request``.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

_LogF = Callable[[str], None]


class ProgressReporter:
    """A thin client for the ``/api/v1/training`` routes.

    ``daemon_url`` is the base URL of the daemon (e.g. ``http://127.0.0.1:8080``)
    — pass ``None`` / ``""`` and every method becomes a no-op, which is exactly
    how ``synapse-trainer train`` behaves without ``--report-to``.
    """

    def __init__(
        self,
        daemon_url: str | None,
        *,
        timeout: float = 3.0,
        logf: _LogF | None = None,
        enabled: bool = True,
    ) -> None:
        self.base = (daemon_url or "").rstrip("/")
        self.timeout = timeout
        self._log: _LogF = logf or (lambda _msg: None)
        self.enabled = bool(enabled and self.base)
        self.run_id: str | None = None
        self.progress_url: str | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(
        self,
        *,
        name: str,
        recipe: Any,
        epochs_total: int,
        trainer_version: str,
    ) -> bool:
        """Register the run.  Returns True once a progress URL is known."""
        if not self.enabled:
            return False
        resp = self._post(
            self.base + "/api/v1/training",
            {
                "name": name,
                "recipe": recipe,
                "epochs_total": int(epochs_total),
                "trainer_version": trainer_version,
            },
            expect_json=True,
        )
        if not resp or not resp.get("id"):
            self._log(
                f"progress: could not register the run with {self.base} "
                "— continuing without live reporting"
            )
            return False
        self.run_id = str(resp["id"])
        self.progress_url = resp.get("progress_url") or (
            self.base + f"/api/v1/training/{self.run_id}/progress"
        )
        self._log(f"progress: run {self.run_id} registered with {self.base}")
        return True

    def handle(self, msg: dict[str, Any]) -> None:
        """POST one ``train_iter`` dict — an ``epoch`` dict or the ``done`` dict.

        A no-op until :meth:`start` has succeeded, so it is safe to wire
        unconditionally as ``run_training(on_epoch=reporter.handle)``.
        """
        if not self.progress_url:
            return
        self._post(self.progress_url, msg, expect_json=False)

    # Explicit aliases for callers that prefer them to a single handle().
    def epoch(self, msg: dict[str, Any]) -> None:
        self.handle(msg)

    def done(self, metrics: dict[str, Any]) -> None:
        if not self.progress_url:
            return
        self._post(
            self.progress_url,
            {"event": "done", "metrics": metrics},
            expect_json=False,
        )

    def fail(self, reason: str) -> None:
        if not self.enabled or not self.run_id:
            return
        self._post(
            self.base + f"/api/v1/training/{self.run_id}/fail",
            {"reason": str(reason)[:2000]},
            expect_json=False,
        )

    # ------------------------------------------------------------------- transport
    def _post(self, url: str, obj: Any, *, expect_json: bool) -> dict[str, Any] | None:
        try:
            data = json.dumps(obj).encode("utf-8")
            req = urllib.request.Request(  # noqa: S310 - operator-supplied daemon URL
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                raw = r.read()
            if expect_json and raw:
                return json.loads(raw.decode("utf-8"))
            return {}
        except Exception as exc:  # telemetry must never break training
            self._log(f"progress: POST {url} failed: {exc}")
            return None
