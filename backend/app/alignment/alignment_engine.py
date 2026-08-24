from dataclasses import dataclass, asdict
from typing import Dict, List

from ..intent.intent_contract import IntentContract
from ..parser.command_parser import CommandAnalysis


@dataclass
class AlignmentResult:
    """
    Compares what the user intended with what the command
    actually attempts to do.
    """

    score: int
    status: str

    intent_operation: str
    command_operation: str

    operation_match: bool
    target_match: bool

    violations: List[str]
    evidence: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


class IntentCommandAligner:
    """
    Intent ↔ Command alignment engine.

    Core security idea:

        User Intent != Command Intent
        ------------------------------
        The command must not exceed the user's stated goal.
    """

    # ---------------------------------------------------------
    # Operations considered compatible
    # ---------------------------------------------------------

    COMPATIBLE_OPERATIONS = {
        "READ": {
            "READ",
        },

        "CREATE": {
            "CREATE",
        },

        "DELETE": {
            "DELETE",
        },

        "COPY": {
            "COPY",
        },

        "MOVE": {
            "MOVE",
        },

        "PERMISSION_CHANGE": {
            "PERMISSION_CHANGE",
        },

        "PROCESS_CONTROL": {
            "PROCESS_CONTROL",
        },

        "NETWORK": {
            "NETWORK",
        },

        "PACKAGE_CHANGE": {
            "PACKAGE_CHANGE",
        },

        "SYSTEM_CONFIGURATION": {
            "SYSTEM_CONFIGURATION",
        },
    }

    # ---------------------------------------------------------
    # Operations that must never be silently substituted
    # ---------------------------------------------------------

    HIGH_RISK_OPERATIONS = {
        "DELETE",
        "PERMISSION_CHANGE",
        "PROCESS_CONTROL",
        "PACKAGE_CHANGE",
        "SYSTEM_CONFIGURATION",
    }

    # ---------------------------------------------------------
    # Main alignment function
    # ---------------------------------------------------------

    def align(
        self,
        contract: IntentContract,
        command: CommandAnalysis,
    ) -> AlignmentResult:

        violations: List[str] = []
        evidence: List[str] = []

        # -----------------------------------------------------
        # 1. Operation comparison
        # -----------------------------------------------------

        intent_operation = (
            contract.operation
        )

        command_operation = (
            command.operation
        )

        compatible = self.COMPATIBLE_OPERATIONS.get(
            intent_operation,
            set(),
        )

        operation_match = (
            command_operation
            in compatible
        )

        if operation_match:

            evidence.append(
                "Command operation matches the user's intended operation."
            )

        else:

            violations.append(
                "Command operation does not match the user's intent."
            )

        # -----------------------------------------------------
        # 2. Target comparison
        # -----------------------------------------------------

        target_match = self._target_matches(
            contract.target,
            command.targets,
        )

        if contract.target == "UNSPECIFIED":

            evidence.append(
                "User did not specify a concrete target."
            )

        elif target_match:

            evidence.append(
                "Command target is consistent with the intended target."
            )

        else:

            violations.append(
                "Command target does not match the intended target."
            )

        # -----------------------------------------------------
        # 3. Intent contract violations
        # -----------------------------------------------------

        self._check_contract_violations(
            contract,
            command,
            violations,
        )

        # -----------------------------------------------------
        # 4. Calculate score
        # -----------------------------------------------------

        score = 100

        if not operation_match:

            score -= 60

        if (
            contract.target != "UNSPECIFIED"
            and not target_match
        ):

            score -= 25

        # Any explicit contract violation is serious.
        score -= min(
            len(violations) * 20,
            60,
        )

        # Never allow negative alignment.
        score = max(
            score,
            0,
        )

        # -----------------------------------------------------
        # 5. Determine status
        # -----------------------------------------------------

        status = self._status(
            score,
            violations,
        )

        # -----------------------------------------------------
        # 6. Evidence for risky command
        # -----------------------------------------------------

        if command.destructive:

            evidence.append(
                "Command performs a destructive operation."
            )

        if command.privilege == "ELEVATED":

            evidence.append(
                "Command requests elevated privilege."
            )

        if command.network:

            evidence.append(
                "Command performs network activity."
            )

        if command.sensitive_target:

            evidence.append(
                "Command touches a sensitive system target."
            )

        return AlignmentResult(
            score=score,
            status=status,
            intent_operation=intent_operation,
            command_operation=command_operation,
            operation_match=operation_match,
            target_match=target_match,
            violations=violations,
            evidence=evidence,
        )

    # ---------------------------------------------------------
    # Contract violations
    # ---------------------------------------------------------

    @staticmethod
    def _check_contract_violations(
        contract: IntentContract,
        command: CommandAnalysis,
        violations: List[str],
    ) -> None:

        # -----------------------------------------------------
        # Modification forbidden
        # -----------------------------------------------------

        if (
            contract.modification
            == "FORBIDDEN"
            and command.modifies_files
        ):

            violations.append(
                "Command modifies files although the intent "
                "contract forbids modification."
            )

        # -----------------------------------------------------
        # Network forbidden
        # -----------------------------------------------------

        if (
            contract.network
            == "FORBIDDEN"
            and command.network
        ):

            violations.append(
                "Command performs network activity although "
                "the intent contract forbids networking."
            )

        # -----------------------------------------------------
        # Normal privilege expected
        # -----------------------------------------------------

        if (
            contract.privilege == "NORMAL"
            and command.privilege == "ELEVATED"
        ):

            violations.append(
                "Command requests elevated privilege although "
                "the intent contract expects normal privilege."
            )

    # ---------------------------------------------------------
    # Target matching
    # ---------------------------------------------------------

    @staticmethod
    def _target_matches(
        intended_target: str,
        command_targets: List[str],
    ) -> bool:

        if intended_target == "UNSPECIFIED":

            return True

        if not command_targets:

            return False

        normalized_intent = (
            intended_target.rstrip("/")
        )

        for target in command_targets:

            normalized_target = (
                target.rstrip("/")
            )

            # Exact match
            if normalized_target == normalized_intent:

                return True

            # Command may operate inside the intended directory.
            if normalized_target.startswith(
                normalized_intent + "/"
            ):

                return True

        return False

    # ---------------------------------------------------------
    # Status
    # ---------------------------------------------------------

    @staticmethod
    def _status(
        score: int,
        violations: List[str],
    ) -> str:

        if violations:

            if score < 40:

                return "BLOCK"

            return "REVIEW"

        if score >= 90:

            return "ALIGNED"

        if score >= 70:

            return "PARTIAL"

        return "MISMATCH"


# =============================================================
# Standalone test
# =============================================================

if __name__ == "__main__":

    from ..intent.intent_engine import (
        IntentEngine,
    )

    from ..parser.command_parser import (
        LinuxCommandParser,
    )

    engine = IntentEngine()

    builder_module = (
        __import__(
            "backend.app.intent.intent_contract",
            fromlist=[
                "IntentContractBuilder"
            ],
        )
    )

    IntentContractBuilder = (
        builder_module.IntentContractBuilder
    )

    contract_builder = (
        IntentContractBuilder()
    )

    parser = LinuxCommandParser()

    aligner = IntentCommandAligner()

    test_cases = [

        (
            "I want to view files in ~/Downloads",
            "ls -la ~/Downloads",
        ),

        (
            "I want to view files in ~/Downloads",
            "rm -rf ~/Downloads",
        ),

        (
            "I want to delete an old file in ~/Downloads",
            "rm ~/Downloads/old.txt",
        ),

        (
            "I want to view files in ~/Downloads",
            "sudo cat /etc/passwd",
        ),

        (
            "I want to download a file",
            "curl https://example.com",
        ),

        (
            "I want to create a folder in ~/Projects",
            "mkdir ~/Projects/demo",
        ),
    ]

    print("=" * 70)
    print(
        "SafeShell AI - Intent/Command Alignment Test"
    )
    print("=" * 70)

    for goal, command in test_cases:

        intent = engine.classify(
            goal
        )

        contract = contract_builder.build(
            goal,
            intent,
        )

        analysis = parser.parse(
            command
        )

        result = aligner.align(
            contract,
            analysis,
        )

        print()
        print("USER INTENT:")
        print(goal)

        print()
        print("COMMAND:")
        print(command)

        print()
        print("ALIGNMENT SCORE:")
        print(result.score)

        print()
        print("STATUS:")
        print(result.status)

        print()
        print("INTENT OPERATION:")
        print(result.intent_operation)

        print()
        print("COMMAND OPERATION:")
        print(result.command_operation)

        print()
        print("OPERATION MATCH:")
        print(result.operation_match)

        print()
        print("TARGET MATCH:")
        print(result.target_match)

        print()
        print("VIOLATIONS:")

        if result.violations:

            for violation in result.violations:
                print(
                    " -",
                    violation,
                )

        else:

            print(
                " - None"
            )

        print()
        print("EVIDENCE:")

        for item in result.evidence:

            print(
                " -",
                item,
            )

        print("-" * 70)