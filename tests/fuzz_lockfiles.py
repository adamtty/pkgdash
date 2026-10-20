"""Coverage-guided fuzzing of the lockfile parsers with Atheris (Linux x86-64; CI runs it).

Lockfiles come from any project in the projects folder, other people's code included, so whatever
they contain, every parser must return clean (name, version) pairs and never raise: one bad file
would otherwise stop the malware and CVE checks for every project.

    pip install --require-hashes -r tests/requirements-fuzz.txt
    python tests/fuzz_lockfiles.py tests/fuzz-corpus/lockfiles -max_total_time=60
"""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp(prefix="pkgdash-fuzz-")  # server.py keeps its state under HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import atheris  # noqa: E402

with atheris.instrument_imports():
    import server  # noqa: E402

NAMES = sorted(server.LOCKFILES)


def TestOneInput(data):
    text = data.decode("utf-8", "replace")
    for fname in NAMES:  # every input goes through every parser
        for name, version in server.lock_deps(fname, text):
            assert isinstance(name, str) and name, (fname, name)
            assert isinstance(version, str) and version and ":" not in version and "/" not in version, (fname, version)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
