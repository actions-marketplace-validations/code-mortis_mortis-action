# Contributing to Mortis Action

Use Python 3.13 and Git. Create a virtual environment, install the test
dependencies, and run the offline test suite.

```sh
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
python -B -m unittest discover -s tests
```

Tests use temporary Git repositories and mock GitHub and provider calls.
Keep the test dependency pins aligned with the corresponding runtime pins in
`run_mortis.py`.

Open an issue for a reproducible bug or a feature proposal. Keep pull requests
focused, explain the change, link related issues, and report the checks you ran.
Use synthetic fixtures for behavior changes. Share sanitized excerpts of logs
and reports in issues and pull requests.

Report vulnerabilities privately using the [security policy](SECURITY.md).
