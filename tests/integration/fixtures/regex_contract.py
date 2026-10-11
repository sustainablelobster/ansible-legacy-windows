"""Own inert files and inspect real regex/update-selection helpers on Windows."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import os
import sys
import uuid

TEXTS = {
    "none": "done",
    "lf": "done\n",
    "crlf": "done\r\n",
    "double": "done\n\n",
    "more": "done\nmore",
    "named": "donedone\n",
}
NAMES = ("done.txt", "DONE2.txt", "Å.txt")


def _observe(root, nonce):
    with open(os.path.join(root, "owner.json"), encoding="utf-8") as stream:
        owner = json.load(stream)
    assert owner == {"root": root, "nonce": nonce}
    files = {}
    for directory, _, names in os.walk(root):
        for name in names:
            path = os.path.join(directory, name)
            with open(path, "rb") as stream:
                files[os.path.relpath(path, root)] = hashlib.sha256(
                    stream.read()
                ).hexdigest()
    return {"root": root, "nonce": nonce, "files": files}


def _prepare(root):
    assert os.path.basename(root).startswith("legacy-windows-regex-contract-")
    assert os.listdir(root) == ["helpers"]
    nonce = uuid.uuid4().hex
    with open(os.path.join(root, "owner.json"), "w", encoding="utf-8") as stream:
        json.dump({"root": root, "nonce": nonce}, stream, sort_keys=True)
    os.mkdir(os.path.join(root, "texts"))
    os.mkdir(os.path.join(root, "names"))
    for name, text in TEXTS.items():
        with open(os.path.join(root, "texts", name), "wb") as stream:
            stream.write(text.encode("utf-8"))
    for name in NAMES:
        with open(os.path.join(root, "names", name), "wb") as stream:
            stream.write(b"owned regex filename")
    return _observe(root, nonce)


def _updates(root):
    # These are actual helpers with controlled title/KB inputs, not WUA evidence.
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(root, "helpers"))
    # pylint: disable=import-outside-toplevel,import-error,protected-access
    import legacy_windows_updates as updates

    cases = [
        ({"title": "done\n", "kb": []}, r"done\Z", True),
        ({"title": "done\n", "kb": []}, r"done\z", False),
        ({"title": "done", "kb": ["KB123", "KB456"]}, r"doneKB123 KB456\Z", True),
    ]
    results = []
    for info, pattern, expected in cases:
        matched = updates._matches(info, [pattern])
        assert matched is expected
        results.append({"input": info, "pattern": pattern, "matched": matched})
    try:
        updates._matches({"title": "done", "kb": []}, [r"done(?m)$"])
    except ValueError as error:
        assert "non-prefix inline options" in str(error)
        results.append({"pattern": r"done(?m)$", "error": str(error)})
    else:
        raise AssertionError("Positional flags were silently accepted")
    return {"python": list(sys.version_info[:3]), "selection": results}


def main():
    """Run an owned-file or controlled helper operation on actual Python 3.4.4."""
    assert sys.version_info[:3] == (3, 4, 4)
    operation, root = sys.argv[1:3]
    if operation == "prepare":
        result = _prepare(root)
    elif operation == "observe":
        result = _observe(root, sys.argv[3])
    else:
        assert operation == "updates"
        result = _updates(root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
