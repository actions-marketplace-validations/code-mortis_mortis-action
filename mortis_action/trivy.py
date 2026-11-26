"""Install the pinned, checksum-verified Trivy release for scans."""

import hashlib
import os
import shutil
import subprocess
import tarfile

TRIVY_VERSION = "0.76.2"
TRIVY_ASSETS = {
    "X64": ("64bit", "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"),
    "ARM64": ("ARM64", "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3"),
}


def install_trivy(directory, environment):
    architecture = os.environ["RUNNER_ARCH"]
    if architecture not in TRIVY_ASSETS:
        raise ValueError("Scans require a Linux X64 or ARM64 runner.")
    arch, digest = TRIVY_ASSETS[architecture]
    asset = f"trivy_{TRIVY_VERSION}_Linux-{arch}.tar.gz"
    archive = directory / asset
    subprocess.run(
        [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "180",
            "--output",
            archive,
            f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{asset}",
        ],
        check=True,
        env=environment,
    )
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("Trivy release checksum mismatch.")
    with tarfile.open(archive) as package:
        member = package.getmember("trivy")
        if not member.isfile():
            raise ValueError("Expected a regular Trivy binary.")
        binary = directory / "trivy"
        with package.extractfile(member) as source, binary.open("xb") as target:
            shutil.copyfileobj(source, target)
        binary.chmod(0o700)
    archive.unlink()
