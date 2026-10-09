"""Build cmd.exe commands for Python 3.4.4-compatible Windows payloads."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ntpath
from collections.abc import Iterable

# Ansible exposes its plugin API without Python typing metadata.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.plugins.shell import ShellBase  # type: ignore[import-untyped]
from ansible.plugins.shell import cmd as ansible_cmd

DOCUMENTATION = r"""
name: cmd
short_description: Run legacy Windows Python payloads through cmd.exe
description:
  - Uses the configured Python interpreter for temporary files and directories.
  - Requires a connection that executes commands through C(cmd.exe) and supports
    transferring files.
  - Supports synchronous tasks with process-local environment overrides.
  - Native payload actions support C(become_method=runas) through Windows APIs;
    the shell itself does not launch a privilege-escalation executable.
version_added: '1.0.0'
options:
  async_dir:
    description:
      - Directory containing asynchronous job cache files read by C(async_status).
      - This option does not enable launching asynchronous Python payloads.
    default: '%USERPROFILE%\.ansible_async'
    ini:
      - section: powershell
        key: async_dir
    vars:
      - name: ansible_async_dir
  python_interpreter:
    description:
      - Absolute, unquoted Windows path to a Python 3.4.4 or newer executable.
      - Interpreter discovery and command-line arguments are not supported.
    type: str
    required: true
    vars:
      - name: ansible_python_interpreter
  remote_tmp:
    description:
      - Target directory for task files. Environment variables are expanded
        by Python on the target before the directory is created.
    type: str
    default: '%TEMP%'
    vars:
      - name: ansible_remote_tmp
"""

_CMD_QUOTER = ansible_cmd.ShellModule()


# ShellBase is Ansible's untyped extension interface, required by its loader.
class ShellModule(ShellBase):  # type: ignore[misc]
    """Provide Windows paths and Python housekeeping to standard connections."""

    COMPATIBLE_SHELLS: frozenset[str] = frozenset()
    SHELL_FAMILY = "cmd"
    _IS_WINDOWS = True
    _SHELL_REDIRECT_ALLNULL = ">nul 2>&1"
    _SHELL_AND = "&&"

    def env_prefix(self, **kwargs: object) -> str:
        """Launch the task with literal, process-local environment overrides.

        :param kwargs: Environment names and values supplied by the task.
        :returns: A Python launcher prefix, or an empty string without overrides.
        :raises AnsibleError: If a name or value cannot form a Windows environment.
        """
        if not kwargs:
            return ""
        overrides = {}
        for name, value in kwargs.items():
            text = str(value)
            if not name or "=" in name or "\0" in name or "\0" in text:
                raise AnsibleError(
                    "Task environment names must be nonempty and contain no '=' "
                    "or NUL; values must contain no NUL"
                )
            overrides[name] = text
        # Encoding values in Python source keeps cmd.exe expansion and metacharacters
        # out of the environment data. The child inherits ordinary handles and PATH.
        # Normalize names on target Python, as Windows os.environ does for inheritance.
        return self._python_prefix(
            "import os, subprocess, sys\n"
            "environment = dict(os.environ)\n"
            "environment.update({name.upper(): value for name, value in "
            f"{overrides!r}.items()}})\n"
            "sys.exit(subprocess.call(sys.argv[1:], env=environment))\n"
        )

    def join_path(self, *args: str) -> str:
        """Join target paths using Windows separators.

        :param args: Windows path components.
        :returns: The joined path, including a requested trailing separator.
        """
        return ntpath.join(*(part.replace("/", "\\") for part in args))

    def get_remote_filename(self, pathname: str) -> str:
        """Preserve the module's filename and extension during transfer.

        :param pathname: Controller or target pathname.
        :returns: Its final path component.
        """
        return ntpath.basename(pathname)

    def path_has_trailing_slash(self, path: str) -> bool:
        """Recognize either Windows path separator.

        :param path: Target path to inspect.
        :returns: Whether the path ends with a separator.
        """
        return path.endswith(("/", "\\"))

    def quote(self, cmd: str) -> str:
        """Quote one argument using Ansible's cmd.exe quoting implementation.

        :param cmd: Literal argument value.
        :returns: The escaped argument.
        """
        return str(_CMD_QUOTER.quote(cmd))

    def join(self, cmd_parts: Iterable[str]) -> str:
        """Quote a command and its arguments for cmd.exe.

        :param cmd_parts: Executable followed by its literal arguments.
        :returns: Literal argument text, without complete-command grouping.
        """
        return str(_CMD_QUOTER.join(list(cmd_parts)))

    @staticmethod
    def prepare_command(command: str) -> str:
        """Preserve the executable boundary of one complete CMD command.

        :param command: Fully assembled command, including an environment prefix.
        :returns: The execution-ready command; already grouped commands are kept.
        """
        # CMD /c can strip the leading executable's quotes. Group the complete
        # command, not its argv or environment prefix, to preserve that boundary.
        return f"({command})" if command.startswith('"') else command

    def build_module_command(
        self,
        env_string: str,
        shebang: str | None,
        cmd: str,
        arg_path: str | None = None,
    ) -> str:
        """Build one complete CMD command without losing executable quotes.

        :param env_string: Literal process-local environment launcher prefix.
        :param shebang: Interpreter directive beginning with ``#!``, or None.
        :param cmd: Module's target path.
        :param arg_path: Optional path containing module arguments.
        :returns: The complete command with its executable boundary preserved.
        """
        command = super().build_module_command(env_string, shebang, cmd, arg_path)
        return self.prepare_command(str(command))

    def _python_prefix(self, script: str) -> str:
        interpreter = self.get_option("python_interpreter")
        if (
            not isinstance(interpreter, str)
            or not ntpath.isabs(interpreter)
            or not ntpath.splitdrive(interpreter)[0]
            or any(character in interpreter for character in '\r\n\0"')
        ):
            raise AnsibleError(
                "Set ansible_python_interpreter to the absolute, unquoted "
                "Windows path of Python 3.4.4 or newer; discovery is not supported"
            )
        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        expression = f"exec(__import__('base64').b64decode('{encoded}'))"
        return self.join([interpreter, "-c", expression])

    def _python_command(self, script: str) -> str:
        return self.prepare_command(self._python_prefix(script))

    def mkdtemp(
        self,
        basefile: str | None = None,
        system: bool = False,
        mode: int = 0o700,
        tmpdir: str | None = None,
    ) -> str:
        """Create a fresh task directory and return its absolute path as UTF-8.

        :param basefile: Unique directory name, generated when omitted.
        :param system: Whether core requests cross-user staging; authenticated
            read/execute access is granted later by the native runas wrapper.
        :param mode: POSIX mode, unused because Windows inherits parent ACLs.
        :param tmpdir: Parent directory, or the configured remote_tmp.
        :returns: The Python command to create the directory.
        :raises AnsibleError: If the temporary directory name is invalid.
        """
        # Both modes create private, ordinary Windows staging. Do not translate
        # core's cross-user flag into a globally readable temporary directory.
        if basefile is None:
            basefile = str(self._generate_temp_dir_name())
        if (
            not basefile
            or ntpath.basename(basefile) != basefile
            or basefile in (".", "..")
        ):
            raise AnsibleError("Temporary directory name must be one path component")
        root = tmpdir if tmpdir is not None else self.get_option("remote_tmp")
        return self._python_command(
            "import os, sys\n"
            f"root = os.path.expanduser(os.path.expandvars({root!r}))\n"
            "if not os.path.isabs(root):\n"
            "    raise ValueError('ansible_remote_tmp must resolve to an absolute path')\n"
            "os.makedirs(root, exist_ok=True)\n"
            f"path = os.path.join(root, {basefile!r})\n"
            "os.mkdir(path)\n"
            "sys.stdout.buffer.write((path + '\\n').encode('utf-8'))\n"
        )

    def remove(self, path: str, recurse: bool = False) -> str:
        """Remove a target without traversing directory reparse points.

        :param path: Literal path to remove, without environment expansion.
        :param recurse: Whether to remove a directory's contents as well.
        :returns: The Python removal command.
        """
        return self._python_command(
            "import ctypes, os\n"
            "kernel = ctypes.WinDLL('kernel32', use_last_error=True)\n"
            "attributes = kernel.GetFileAttributesW\n"
            "attributes.argtypes = [ctypes.c_wchar_p]\n"
            "attributes.restype = ctypes.c_uint32\n"
            "def remove(path):\n"
            "    value = attributes(path)\n"
            "    if value == 0xffffffff:\n"
            "        error = ctypes.get_last_error()\n"
            "        if error in (2, 3):\n"
            "            return\n"
            "        raise ctypes.WinError(error)\n"
            "    try:\n"
            "        if value & 0x10:\n"
            # Python 3.4's islink/rmtree do not recognize NTFS junctions.
            f"            if {recurse!r} and not value & 0x400:\n"
            "                for name in os.listdir(path):\n"
            "                    remove(os.path.join(path, name))\n"
            "            os.rmdir(path)\n"
            "        else:\n"
            "            os.remove(path)\n"
            "    except FileNotFoundError:\n"
            "        pass\n"
            f"path = {path!r}\n"
            "if path:\n"
            "    remove(os.path.normpath(path))\n"
        )

    def exists(self, path: str) -> str:
        """Test a literal target path using the command exit status.

        :param path: Target path to inspect.
        :returns: A command returning zero when the path exists, one otherwise.
        """
        return self._python_command(
            f"import os, sys\nsys.exit(0 if os.path.exists({path!r}) else 1)\n"
        )

    def expand_user(self, user_home_path: str, username: str = "") -> str:
        """Expand the connected user's home and target environment variables.

        :param user_home_path: Path to expand on the target.
        :param username: Alternate account name, which is unsupported.
        :returns: A Python command returning the expanded path as UTF-8.
        :raises AnsibleError: If expansion names another account.
        """
        if username or (
            user_home_path.startswith("~")
            and user_home_path != "~"
            and not user_home_path.startswith(("~/", "~\\"))
        ):
            raise AnsibleError("Home expansion for named Windows users is unsupported")
        return self._python_command(
            "import os, sys\n"
            f"path = os.path.expanduser(os.path.expandvars({user_home_path!r}))\n"
            "sys.stdout.buffer.write((path + '\\n').encode('utf-8'))\n"
        )

    def pwd(self) -> str:
        """Return a command that prints the target working directory as UTF-8.

        :returns: The Python command for retrieving the working directory.
        """
        return self._python_command(
            "import os, sys\nsys.stdout.buffer.write((os.getcwd() + '\\n').encode('utf-8'))\n"
        )
