"""The live-progress reporter (synapse_trainer.progress).

Runs a real stdlib http.server in a background thread and drives the reporter
against it: register -> progress -> done -> fail, in order, plus the guarantee
that a network failure is swallowed and never raised.  numpy/torch are not
imported here, so this test always runs.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from synapse_trainer.progress import ProgressReporter

RUN_ID = "20260831T120000Z-deadbeef"


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.lock = threading.Lock()

    def add(self, path: str, body: dict) -> None:
        with self.lock:
            self.calls.append((path, body))

    def paths(self) -> list[str]:
        with self.lock:
            return [p for p, _ in self.calls]


@pytest.fixture()
def daemon():
    rec = _Recorder()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence
            pass

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            rec.add(self.path, body)

            if self.path == "/api/v1/training":
                payload = json.dumps(
                    {
                        "id": RUN_ID,
                        "progress_url": f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"
                        f"/api/v1/training/{RUN_ID}/progress",
                    }
                ).encode()
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            # progress + fail
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    try:
        yield f"http://{host}:{port}", rec
    finally:
        srv.shutdown()
        t.join(timeout=2)


def test_register_progress_done_fail_in_order(daemon):
    base, rec = daemon
    r = ProgressReporter(base)

    assert r.start(name="nightly", recipe={"recipe": {"name": "r"}}, epochs_total=3, trainer_version="0.1.0")
    assert r.run_id == RUN_ID
    assert r.progress_url and r.progress_url.endswith(f"/api/v1/training/{RUN_ID}/progress")

    r.handle({"event": "epoch", "epoch": 1, "train_loss": 0.9, "val_loss": 1.0})
    r.epoch({"event": "epoch", "epoch": 2, "train_loss": 0.5, "val_loss": 0.7})
    r.done({"accuracy": 0.95, "macro_f1": 0.94, "confusion": [[5, 0], [1, 4]]})
    r.fail("late failure after done")

    paths = rec.paths()
    assert paths == [
        "/api/v1/training",
        f"/api/v1/training/{RUN_ID}/progress",
        f"/api/v1/training/{RUN_ID}/progress",
        f"/api/v1/training/{RUN_ID}/progress",
        f"/api/v1/training/{RUN_ID}/fail",
    ]

    # register body carries the §19.8 metadata
    _, reg_body = rec.calls[0]
    assert reg_body["name"] == "nightly"
    assert reg_body["epochs_total"] == 3
    assert reg_body["trainer_version"] == "0.1.0"
    assert reg_body["recipe"]["recipe"]["name"] == "r"

    # epoch dicts pass through verbatim
    assert rec.calls[1][1]["epoch"] == 1
    assert rec.calls[2][1]["epoch"] == 2

    # the done dict is wrapped as {"event": "done", "metrics": {...}}
    _, done_body = rec.calls[3]
    assert done_body["event"] == "done"
    assert done_body["metrics"]["accuracy"] == 0.95
    assert done_body["metrics"]["confusion"] == [[5, 0], [1, 4]]

    # the fail body
    assert rec.calls[4][1]["reason"] == "late failure after done"


def test_disabled_without_a_url_is_a_noop():
    r = ProgressReporter(None)
    assert r.start(name="x", recipe={}, epochs_total=1, trainer_version="0.1.0") is False
    # none of these raise or do anything
    r.handle({"event": "epoch", "epoch": 1})
    r.done({"accuracy": 1.0})
    r.fail("nope")
    assert r.run_id is None


def test_network_failure_is_swallowed():
    logs: list[str] = []
    # Port 1 is not listening; every call must fail internally and never raise.
    r = ProgressReporter("http://127.0.0.1:1", timeout=0.25, logf=logs.append)
    assert r.start(name="x", recipe={}, epochs_total=1, trainer_version="0.1.0") is False
    r.handle({"event": "epoch", "epoch": 1})  # progress_url unset -> silent no-op
    r.fail("boom")  # run_id unset -> silent no-op
    assert any("could not register" in m for m in logs)


def test_progress_failure_after_a_good_start_is_swallowed(daemon):
    base, rec = daemon
    r = ProgressReporter(base, timeout=0.5)
    assert r.start(name="x", recipe={}, epochs_total=1, trainer_version="0.1.0")

    # Point the reporter's progress URL at a dead port; posting must not raise.
    r.progress_url = "http://127.0.0.1:1/api/v1/training/x/progress"
    r.handle({"event": "epoch", "epoch": 1})
    r.done({"accuracy": 1.0})
    # Only the register call reached the stub.
    assert rec.paths() == ["/api/v1/training"]
