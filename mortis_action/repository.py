"""Pin Git revisions and fetch pull request objects for review."""

import base64
import os
import re
import subprocess


def resolve(repo, ref, *, env=None):
    if not ref or ref.startswith("-"):
        raise ValueError("Supply a valid commit reference.")
    return subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        text=True,
        stderr=subprocess.DEVNULL,
        env=env,
    ).strip()


def review_range(repo, base, head, *, env=None):
    shallow = subprocess.check_output(["git", "-C", repo, "rev-parse", "--is-shallow-repository"], text=True, env=env)
    ancestor = subprocess.run(["git", "-C", repo, "merge-base", base, head], check=False, capture_output=True, env=env)
    if shallow.strip() == "true" or ancestor.returncode != 0:
        raise ValueError(
            "A review needs complete Git history and a common ancestor. Use checkout with fetch-depth: 0."
        )
    return ["review", "--base", base, "--head", head], base


def fetch_pull_request(repo, pr):
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    if any(re.fullmatch(r"[0-9a-f]{40}", sha) is None for sha in (base, head)):
        raise ValueError("GitHub did not return valid PR commit IDs.")
    number = int(pr["number"])
    url = f"{os.environ['GITHUB_SERVER_URL'].rstrip('/')}/{os.environ['GITHUB_REPOSITORY']}.git"
    token = base64.b64encode(f"x-access-token:{os.environ['MORTIS_GITHUB_TOKEN']}".encode()).decode()
    # Keep Git configuration and credentials scoped to this fetch.
    env = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    subprocess.run(["git", "init", "--bare", "--quiet", "--template=", repo], check=True, env=env)
    subprocess.run(
        ["git", "-C", repo, "-c", "http.followRedirects=false",
         "--config-env=http.extraHeader=MORTIS_GIT_AUTH", "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
         url, f"{base}:refs/mortis/base", f"refs/pull/{number}/head:refs/mortis/head"],
        check=True,
        env={**env, "MORTIS_GIT_AUTH": f"Authorization: Basic {token}"},
    )
    if resolve(repo, "refs/mortis/base", env=env) != base or resolve(repo, "refs/mortis/head", env=env) != head:
        return None, "The PR changed while fetching its commits"
    return review_range(repo, base, head, env=env)
