"""Install the pinned, checksum-verified Trivy release for scans."""

import hashlib
import os
import shutil
import subprocess
import tarfile

TRIVY_VERSION = "0.76.0"
TRIVY_ASSETS = {
    "X64": ("64bit", "e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7"),
    "ARM64": ("ARM64", "aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c"),
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
