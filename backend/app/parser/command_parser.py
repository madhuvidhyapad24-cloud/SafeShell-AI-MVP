from dataclasses import dataclass, asdict
from typing import Dict, List
import re
import shlex


@dataclass
class CommandAnalysis:
    """
    Structured representation of a Linux command.

    This parser analyzes command structure only.
    It NEVER executes the command.
    """

    raw_command: str

    executable: str
    operation: str

    targets: List[str]

    privilege: str

    destructive: bool
    network: bool
    modifies_files: bool

    uses_wildcard: bool
    uses_pipe: bool
    uses_redirect: bool
    uses_command_chaining: bool

    sensitive_target: bool

    risk_signals: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


class LinuxCommandParser:
    """
    Static Linux command parser.

    Responsibilities:

    1. Identify the executable.
    2. Identify the intended operation.
    3. Extract relevant filesystem/network targets.
    4. Detect privilege escalation.
    5. Detect shell constructs.
    6. Detect potentially sensitive targets.

    The parser is deliberately separate from execution.
    """

    # ---------------------------------------------------------
    # Command categories
    # ---------------------------------------------------------

    READ_COMMANDS = {
        "ls",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "find",
        "stat",
        "file",
        "pwd",
        "du",
        "df",
    }

    CREATE_COMMANDS = {
        "touch",
        "mkdir",
    }

    DELETE_COMMANDS = {
        "rm",
        "rmdir",
    }

    COPY_COMMANDS = {
        "cp",
    }

    MOVE_COMMANDS = {
        "mv",
    }

    PERMISSION_COMMANDS = {
        "chmod",
        "chown",
        "chgrp",
    }

    PROCESS_COMMANDS = {
        "kill",
        "pkill",
        "killall",
    }

    NETWORK_COMMANDS = {
        "curl",
        "wget",
        "scp",
        "sftp",
        "ssh",
        "nc",
        "netcat",
    }

    PACKAGE_COMMANDS = {
        "apt",
        "apt-get",
        "dnf",
        "yum",
        "pacman",
        "snap",
        "pip",
    }

    # ---------------------------------------------------------
    # Sensitive filesystem locations
    # ---------------------------------------------------------

    SENSITIVE_PATHS = {
        "/etc",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/boot",
        "/root",
        "/var",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/sys",
        "/proc",
        "/dev",
    }

    # ---------------------------------------------------------
    # Parse
    # ---------------------------------------------------------

    def parse(
        self,
        command: str,
    ) -> CommandAnalysis:

        raw = command.strip()

        if not raw:

            return self._unknown_analysis(
                raw_command="",
                signal="Empty command",
            )

        # -----------------------------------------------------
        # Shell structure detection
        # -----------------------------------------------------

        uses_pipe = "|" in raw

        uses_redirect = bool(
            re.search(
                r"(?:^|[^<])>(?:[^=]|$)|>>|<",
                raw,
            )
        )

        uses_command_chaining = bool(
            re.search(
                r"&&|\|\||;",
                raw,
            )
        )

        uses_wildcard = bool(
            re.search(
                r"[*?\[]",
                raw,
            )
        )

        # -----------------------------------------------------
        # Tokenization
        # -----------------------------------------------------

        try:

            tokens = shlex.split(
                raw,
                posix=True,
            )

        except ValueError:

            return self._unknown_analysis(
                raw_command=raw,
                signal=(
                    "Command contains invalid "
                    "or unbalanced quoting"
                ),
                uses_wildcard=uses_wildcard,
                uses_pipe=uses_pipe,
                uses_redirect=uses_redirect,
                uses_command_chaining=(
                    uses_command_chaining
                ),
            )

        if not tokens:

            return self._unknown_analysis(
                raw_command=raw,
                signal="No executable detected",
                uses_wildcard=uses_wildcard,
                uses_pipe=uses_pipe,
                uses_redirect=uses_redirect,
                uses_command_chaining=(
                    uses_command_chaining
                ),
            )

        # -----------------------------------------------------
        # Privilege detection
        # -----------------------------------------------------

        privilege = "NORMAL"

        command_tokens = list(tokens)

        if command_tokens[0] == "sudo":

            privilege = "ELEVATED"

            command_tokens = command_tokens[1:]

            # Skip common sudo options.
            while (
                command_tokens
                and command_tokens[0].startswith("-")
            ):
                command_tokens = command_tokens[1:]

        if not command_tokens:

            return self._unknown_analysis(
                raw_command=raw,
                signal=(
                    "Privilege escalation detected "
                    "without a command"
                ),
                privilege=privilege,
                uses_wildcard=uses_wildcard,
                uses_pipe=uses_pipe,
                uses_redirect=uses_redirect,
                uses_command_chaining=(
                    uses_command_chaining
                ),
            )

        # -----------------------------------------------------
        # Extract first command only
        # -----------------------------------------------------

        first_command_tokens = self._first_command_tokens(
            command_tokens
        )

        if not first_command_tokens:

            return self._unknown_analysis(
                raw_command=raw,
                signal="Unable to identify command",
                privilege=privilege,
                uses_wildcard=uses_wildcard,
                uses_pipe=uses_pipe,
                uses_redirect=uses_redirect,
                uses_command_chaining=(
                    uses_command_chaining
                ),
            )

        # -----------------------------------------------------
        # Executable
        # -----------------------------------------------------

        executable = first_command_tokens[0]

        executable_name = executable.split("/")[-1]

        # -----------------------------------------------------
        # Operation
        # -----------------------------------------------------

        operation = self._detect_operation(
            executable_name,
            first_command_tokens,
        )

        # -----------------------------------------------------
        # Targets
        # -----------------------------------------------------

        targets = self._extract_targets(
            executable_name,
            first_command_tokens,
        )

        # -----------------------------------------------------
        # Redirection targets
        # -----------------------------------------------------

        redirect_targets = self._extract_redirect_targets(
            raw
        )

        if redirect_targets:

            targets.extend(
                redirect_targets
            )

        # Remove duplicates while preserving order.
        targets = list(
            dict.fromkeys(targets)
        )

        # -----------------------------------------------------
        # Security properties
        # -----------------------------------------------------

        destructive = (
            operation == "DELETE"
        )

        modifies_files = operation in {
            "CREATE",
            "DELETE",
            "COPY",
            "MOVE",
            "PERMISSION_CHANGE",
        }

        # Redirection can modify a file even when the
        # executable itself is read-oriented.
        if uses_redirect:
            modifies_files = True

        network = (
            operation == "NETWORK"
        )

        sensitive_target = (
            self._contains_sensitive_target(
                targets
            )
        )

        # -----------------------------------------------------
        # Risk signals
        # -----------------------------------------------------

        risk_signals: List[str] = []

        if privilege == "ELEVATED":

            risk_signals.append(
                "Elevated privilege via sudo"
            )

        if destructive:

            risk_signals.append(
                "Destructive filesystem operation"
            )

        if network:

            risk_signals.append(
                "Network-capable operation"
            )

        if sensitive_target:

            risk_signals.append(
                "Sensitive filesystem target"
            )

        if uses_wildcard:

            risk_signals.append(
                "Wildcard or glob expansion detected"
            )

        if uses_pipe:

            risk_signals.append(
                "Pipeline detected"
            )

        if uses_redirect:

            risk_signals.append(
                "Shell redirection detected"
            )

            risk_signals.append(
                "Command writes through shell redirection"
            )

        if uses_command_chaining:

            risk_signals.append(
                "Multiple commands may be chained"
            )

        if operation == "UNKNOWN":

            risk_signals.append(
                "Unknown executable or unsupported operation"
            )

        return CommandAnalysis(
            raw_command=raw,
            executable=executable_name,
            operation=operation,
            targets=targets,
            privilege=privilege,
            destructive=destructive,
            network=network,
            modifies_files=modifies_files,
            uses_wildcard=uses_wildcard,
            uses_pipe=uses_pipe,
            uses_redirect=uses_redirect,
            uses_command_chaining=(
                uses_command_chaining
            ),
            sensitive_target=sensitive_target,
            risk_signals=risk_signals,
        )

    # ---------------------------------------------------------
    # First command extraction
    # ---------------------------------------------------------

    @staticmethod
    def _first_command_tokens(
        tokens: List[str],
    ) -> List[str]:

        result: List[str] = []

        for token in tokens:

            if token in {
                "|",
                "||",
                "&&",
                ";",
            }:
                break

            result.append(token)

        return result

    # ---------------------------------------------------------
    # Operation detection
    # ---------------------------------------------------------

    def _detect_operation(
        self,
        executable: str,
        tokens: List[str],
    ) -> str:

        if executable in self.READ_COMMANDS:

            return "READ"

        if executable in self.CREATE_COMMANDS:

            return "CREATE"

        if executable in self.DELETE_COMMANDS:

            return "DELETE"

        if executable in self.COPY_COMMANDS:

            return "COPY"

        if executable in self.MOVE_COMMANDS:

            return "MOVE"

        if executable in self.PERMISSION_COMMANDS:

            return "PERMISSION_CHANGE"

        if executable in self.PROCESS_COMMANDS:

            return "PROCESS_CONTROL"

        if executable in self.NETWORK_COMMANDS:

            return "NETWORK"

        if executable in self.PACKAGE_COMMANDS:

            return "PACKAGE_CHANGE"

        return "UNKNOWN"

    # ---------------------------------------------------------
    # Target extraction
    # ---------------------------------------------------------

    def _extract_targets(
        self,
        executable: str,
        tokens: List[str],
    ) -> List[str]:

        if len(tokens) <= 1:

            return []

        arguments = tokens[1:]

        targets: List[str] = []

        for argument in arguments:

            # -------------------------------------------------
            # Ignore ordinary command options.
            # -------------------------------------------------

            if argument.startswith("-"):

                continue

            # -------------------------------------------------
            # chmod/chown/chgrp have special argument formats.
            # -------------------------------------------------

            if executable == "chmod":

                # Examples:
                # +x
                # 755
                # u+x

                if self._looks_like_permission_spec(
                    argument
                ):
                    continue

            if executable in {
                "chown",
                "chgrp",
            }:

                # user:group or group specification
                if (
                    executable == "chown"
                    and ":" in argument
                    and not self._looks_like_path(
                        argument
                    )
                ):
                    continue

                if (
                    executable == "chgrp"
                    and not self._looks_like_path(
                        argument
                    )
                ):
                    continue

            # -------------------------------------------------
            # Ignore shell operators.
            # -------------------------------------------------

            if argument in {
                "|",
                "||",
                "&&",
                ";",
                ">",
                ">>",
                "<",
            }:

                continue

            targets.append(argument)

        return targets

    # ---------------------------------------------------------
    # Permission-spec detection
    # ---------------------------------------------------------

    @staticmethod
    def _looks_like_permission_spec(
        value: str,
    ) -> bool:

        if re.fullmatch(
            r"[0-7]{3,4}",
            value,
        ):
            return True

        if re.fullmatch(
            r"[ugoa]*[+-=][rwxXstugo-]+",
            value,
        ):
            return True

        return False

    # ---------------------------------------------------------
    # Path detection
    # ---------------------------------------------------------

    @staticmethod
    def _looks_like_path(
        value: str,
    ) -> bool:

        return (
            value.startswith("/")
            or value.startswith("./")
            or value.startswith("../")
            or value.startswith("~/")
        )

    # ---------------------------------------------------------
    # Redirection targets
    # ---------------------------------------------------------

    @staticmethod
    def _extract_redirect_targets(
        command: str,
    ) -> List[str]:

        targets: List[str] = []

        patterns = [
            r">>\s*([^\s|;&]+)",
            r"(?<!>)>(?!>)\s*([^\s|;&]+)",
            r"<\s*([^\s|;&]+)",
        ]

        for pattern in patterns:

            matches = re.findall(
                pattern,
                command,
            )

            for match in matches:

                targets.append(match)

        return targets

    # ---------------------------------------------------------
    # Sensitive target detection
    # ---------------------------------------------------------

    def _contains_sensitive_target(
        self,
        targets: List[str],
    ) -> bool:

        for target in targets:

            normalized = target.rstrip("/")

            for sensitive in self.SENSITIVE_PATHS:

                if (
                    normalized == sensitive
                    or normalized.startswith(
                        sensitive + "/"
                    )
                ):
                    return True

        return False

    # ---------------------------------------------------------
    # Unknown helper
    # ---------------------------------------------------------

    @staticmethod
    def _unknown_analysis(
        raw_command: str,
        signal: str,
        privilege: str = "UNKNOWN",
        uses_wildcard: bool = False,
        uses_pipe: bool = False,
        uses_redirect: bool = False,
        uses_command_chaining: bool = False,
    ) -> CommandAnalysis:

        return CommandAnalysis(
            raw_command=raw_command,
            executable="UNKNOWN",
            operation="UNKNOWN",
            targets=[],
            privilege=privilege,
            destructive=False,
            network=False,
            modifies_files=False,
            uses_wildcard=uses_wildcard,
            uses_pipe=uses_pipe,
            uses_redirect=uses_redirect,
            uses_command_chaining=(
                uses_command_chaining
            ),
            sensitive_target=False,
            risk_signals=[signal],
        )


# =============================================================
# Standalone test
# =============================================================

if __name__ == "__main__":

    parser = LinuxCommandParser()

    test_commands = [

        "ls -la ~/Downloads",

        "cat ~/Downloads/notes.txt",

        "rm ~/Downloads/old.txt",

        "mkdir ~/Projects/demo",

        "cp ~/Downloads/a.txt ~/Documents/",

        "mv ~/Downloads/a.txt ~/Documents/",

        "chmod +x ~/script.sh",

        "sudo cat /etc/passwd",

        "sudo rm /important/file",

        "curl https://example.com",

        "wget https://example.com/file.zip",

        "ls *.txt",

        "cat file.txt | grep hello",

        "rm file1.txt && rm file2.txt",

        "cat > output.txt",

        "unknown-command /tmp/test",
    ]

    print("=" * 70)
    print(
        "SafeShell AI - Linux Command Parser Test"
    )
    print("=" * 70)

    for command in test_commands:

        result = parser.parse(
            command
        )

        print()
        print("COMMAND:")
        print(command)

        print()
        print("ANALYSIS:")

        for key, value in result.to_dict().items():

            print(
                f"{key}: {value}"
            )

        print("-" * 70)