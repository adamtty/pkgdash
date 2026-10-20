"""Coverage-guided fuzzing, with Atheris, of the check that keeps the projects folder inside the home
folder: for any string, the answer is either "no" (None) or "~/…" inside home, not ~/Library.

    python tests/fuzz_projects_root.py -max_total_time=60
"""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp(prefix="pkgdash-fuzz-")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import atheris  # noqa: E402

with atheris.instrument_imports():
    import server  # noqa: E402

HOME = os.path.realpath(os.environ["HOME"])


def TestOneInput(data):
    value = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(256)
    root = server.clean_projects_root(value)
    if root is None:
        return
    assert root.startswith("~/"), (value, root)
    parts = root[2:].split("/")
    assert parts[0] not in ("", ".", "..", "Library") and ".." not in parts, (value, root)
    full = os.path.realpath(os.path.expanduser(root))
    assert full.startswith(HOME + "/"), (value, root, full)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
