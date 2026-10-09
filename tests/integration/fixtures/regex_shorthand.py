"""Seed shorthand inputs through the accepted regex journal and cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later

FILES = (
    "a.txt",
    "É.txt",
    "a\u0301.txt",
    "a\u203f.txt",
    "².txt",
    "Ⅳ.txt",
    "\u08b3.txt",
    "1.txt",
    "\u0de6.txt",
    "\u00a0.txt",
    "a\u200c.txt",
    "😀.txt",
)
TEXT = {
    "digit.txt": "\u0de6",
    "control.txt": "\u001c",
    "mark-boundary.txt": "a\u0301",
    "joiner-boundary.txt": "a\u200c",
}


def main():
    """Reuse only the injected accepted fixture with these explicit inputs."""
    scope = {"__name__": "owned_shorthand_journal"}
    # Execute the literal accepted fixture supplied by the controller rather
    # than copy its independently reviewed protection and cleanup procedures.
    # pylint: disable-next=exec-used
    exec(globals()["REGEX_FIXTURE_SOURCE"], scope)
    scope["FILES"], scope["TEXT"] = FILES, TEXT
    scope["main"]()


if __name__ == "__main__":
    main()
