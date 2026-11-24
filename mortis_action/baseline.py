"""Carry finalized Engine review history between GitHub Actions jobs."""

import base64
import hashlib
import http.client
import io
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

FILENAME = "baseline.enc"
MAX_BYTES = 16 * 1024 * 1024


def state_key(secret):
    key = base64.b64decode(secret.strip(), validate=True)
    if len(key) != 32:
        raise ValueError("MORTIS_STATE_KEY must be a base64-encoded 32-byte key.")
    return key


class ReviewBaseline:
    def __init__(self, api, python, repo, environment, secret):
        state_key(secret)
        self.api = api
        self.python = python
        self.repo = repo
        self.env = {name: environment[name] for name in ("PATH", "XDG_STATE_HOME")}
        self.env["MORTIS_STATE_KEY"] = secret
        # The two trusted PR triggers share history, independently of the checked-out PR workflow.
        workflow = os.environ["GITHUB_WORKFLOW_REF"].partition("@")[0]
        self.namespace = json.dumps([
            "mortis-baseline/v1", os.environ["GITHUB_SERVER_URL"], api.repo, api.number,
            workflow, os.environ["GITHUB_JOB"], os.environ["GITHUB_EVENT_NAME"] == "pull_request",
        ])
        suffix = hashlib.sha256(self.namespace.encode()).hexdigest()[:16]
        self.name = f"mortis-baseline-v1-pr-{api.number}-{suffix}"

    def _state(self, operation, workflow_run, *args, data=None):
        return subprocess.run(
            [self.python, "-I", Path(__file__).resolve(), operation, self.repo, self.namespace, str(workflow_run), *args],
            check=True, input=data, capture_output=True, env=self.env,
        ).stdout

    def restore(self, base, head):
        response = self.api.request("GET", f"/actions/artifacts?name={self.name}&per_page=10")
        candidates = sorted(response["artifacts"], key=lambda row: row["created_at"], reverse=True)
        rejected = False
        for artifact in candidates:
            if artifact["expired"] or artifact["name"] != self.name:
                continue
            try:
                run_id = int(artifact["workflow_run"]["id"])
                archive = self.api.download_artifact(int(artifact["id"]), MAX_BYTES + 64 * 1024)
                with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                    member = zipped.getinfo(FILENAME)
                    if (
                        zipped.namelist() != [FILENAME] or member.file_size > MAX_BYTES
                        or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    ):
                        raise ValueError("Unexpected baseline archive.")
                    with zipped.open(member) as stream:
                        encrypted = stream.read(MAX_BYTES + 1)
                self._state("restore", run_id, base, head, data=encrypted)
                return True
            except (
                KeyError, ValueError, OSError, zipfile.BadZipFile, RuntimeError, subprocess.CalledProcessError,
                http.client.HTTPException, zlib.error,
            ):
                rejected = True
        if rejected:
            raise ValueError("No valid Mortis baseline could be restored.")
        return False

    def save(self, run_id, reports):
        encrypted = self._state("save", os.environ["GITHUB_RUN_ID"], run_id)
        path = reports / FILENAME
        path.write_bytes(encrypted)
        return path


def main():
    # Only this isolated subprocess needs the Engine and encryption libraries or the state key.
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from mortis_engine.history import History, encode

    operation, repo, namespace, workflow_run, *args = sys.argv[1:]
    cipher = AESGCM(state_key(os.environ["MORTIS_STATE_KEY"]))
    associated_data = f"{namespace}:{workflow_run}".encode()
    try:
        with History(repo) as history:
            if operation == "save":
                run_id, = args
                row = history.row(run_id, "review")
                report = history.report(run_id)
                # Engine baseline checks and finding history use these fields from the last finalized run.
                retained = {name: report[name] for name in (
                    "schema_version", "base_sha", "head_sha", "status", "workflow_status", "coverage",
                    "errors", "stage_errors", "settings", "findings", "history", "candidates",
                )}
                plan = {"comparison": json.loads(row["plan"])["comparison"]}
                payload = encode([run_id, row["started"], plan, retained]).encode()
                nonce = os.urandom(12)
                if len(payload) + len(nonce) + 16 > MAX_BYTES:
                    raise ValueError("The review baseline exceeds the artifact size limit.")
                sys.stdout.buffer.write(nonce + cipher.encrypt(nonce, payload, associated_data))
            else:
                base, head = args
                data = sys.stdin.buffer.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError("The review baseline exceeds the artifact size limit.")
                run_id, started, plan, report = json.loads(cipher.decrypt(data[:12], data[12:], associated_data))
                if report["schema_version"] != "mortis.review/v1":
                    raise ValueError("Unsupported baseline report.")
                # Engine 0.1.5 scopes SHA-pinned reviews to their Git arguments. The artifact scopes
                # this row to the PR, and Engine checks the original base, policy and ancestry on reuse.
                with history.db:
                    history.db.execute(
                        "INSERT INTO runs (id, kind, scope, started, plan, report) VALUES (?, 'review', ?, ?, ?, ?)",
                        (run_id, f"{base}...{head}", started, encode(plan), encode(report)),
                    )
    except (InvalidTag, ValueError, KeyError, OSError, sqlite3.Error):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
