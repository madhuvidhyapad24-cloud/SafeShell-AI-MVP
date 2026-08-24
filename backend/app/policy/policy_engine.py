from dataclasses import dataclass, asdict
from typing import Dict, List

from ..intent.intent_contract import IntentContract
from ..parser.command_parser import CommandAnalysis
from ..risk.risk_engine import RiskResult
from ..alignment.alignment_engine import AlignmentResult


@dataclass
class PolicyDecision:
    """
    Final SafeShell security decision.
    """

    decision: str

    confidence: int

    severity: str

    title: str

    explanation: str

    reasons: List[str]

    safer_action: str

    metadata: Dict[str, str]

    def to_dict(self) -> Dict:
        return asdict(self)


class PolicyEngine:
    """
    Final decision-making layer.

    Combines:

        Intent Contract
        Command Analysis
        Risk Result
        Alignment Result

    and produces:

        ALLOW
        REVIEW
        BLOCK

    This layer does NOT execute commands.
    """

    # ---------------------------------------------------------
    # Main policy function
    # ---------------------------------------------------------

    def decide(
        self,
        contract: IntentContract,
        command: CommandAnalysis,
        risk: RiskResult,
        alignment: AlignmentResult,
    ) -> PolicyDecision:

        reasons: List[str] = []

        # -----------------------------------------------------
        # RULE 1
        # Intent/command mismatch
        # -----------------------------------------------------

        if not alignment.operation_match:

            reasons.append(
                "The command operation does not match "
                "the user's stated intent."
            )

            return self._block(
                title="Intent mismatch detected",
                explanation=(
                    "The requested command performs a "
                    "different operation from the user's goal."
                ),
                reasons=reasons,
                safer_action=(
                    "Use a command that performs only "
                    "the requested operation."
                ),
                metadata={
                    "policy_rule": "INTENT_OPERATION_MISMATCH",
                },
            )

        # -----------------------------------------------------
        # RULE 2
        # Contract violations
        # -----------------------------------------------------

        if alignment.violations:

            reasons.extend(
                alignment.violations
            )

            # Elevated privilege against normal intent
            if command.privilege == "ELEVATED":

                return self._block(
                    title="Privilege escalation requires approval",
                    explanation=(
                        "The command requests elevated "
                        "system privileges that were not "
                        "part of the user's stated intent."
                    ),
                    reasons=reasons,
                    safer_action=(
                        "Remove unnecessary privilege "
                        "or explicitly authorize the "
                        "privileged operation."
                    ),
                    metadata={
                        "policy_rule": "UNAUTHORIZED_PRIVILEGE",
                    },
                )

            # Modification forbidden
            if (
                contract.modification
                == "FORBIDDEN"
                and command.modifies_files
            ):

                return self._block(
                    title="Unauthorized modification blocked",
                    explanation=(
                        "The user's intent is non-modifying, "
                        "but the command would change filesystem data."
                    ),
                    reasons=reasons,
                    safer_action=(
                        "Use a read-only command that "
                        "does not modify files."
                    ),
                    metadata={
                        "policy_rule": "MODIFICATION_FORBIDDEN",
                    },
                )

            # Network forbidden
            if (
                contract.network
                == "FORBIDDEN"
                and command.network
            ):

                return self._block(
                    title="Unauthorized network activity blocked",
                    explanation=(
                        "The command performs network activity "
                        "that is not permitted by the intent contract."
                    ),
                    reasons=reasons,
                    safer_action=(
                        "Remove the network operation or "
                        "explicitly authorize network access."
                    ),
                    metadata={
                        "policy_rule": "NETWORK_FORBIDDEN",
                    },
                )

            # Target mismatch
            if not alignment.target_match:

                return self._block(
                    title="Target mismatch blocked",
                    explanation=(
                        "The command targets a location that "
                        "does not match the user's intended target."
                    ),
                    reasons=reasons,
                    safer_action=(
                        "Restrict the command to the "
                        "requested target."
                    ),
                    metadata={
                        "policy_rule": "TARGET_MISMATCH",
                    },
                )

        # -----------------------------------------------------
        # RULE 3
        # Critical risk
        # -----------------------------------------------------

        if risk.severity == "CRITICAL":

            reasons.extend(
                risk.reasons
            )

            return self._block(
                title="Critical-risk command blocked",
                explanation=(
                    "The command contains multiple high-impact "
                    "risk indicators and cannot execute automatically."
                ),
                reasons=reasons,
                safer_action=(
                    "Review the command and reduce its "
                    "privilege, scope, or destructive impact."
                ),
                metadata={
                    "policy_rule": "CRITICAL_RISK",
                },
            )

        # -----------------------------------------------------
        # RULE 4
        # High risk
        # -----------------------------------------------------

        if risk.severity == "HIGH":

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="High-risk command requires review",
                explanation=(
                    "The command is potentially dangerous "
                    "and requires explicit review before execution."
                ),
                reasons=reasons,
                safer_action=(
                    "Verify the target, privilege level, "
                    "and expected impact before continuing."
                ),
                metadata={
                    "policy_rule": "HIGH_RISK",
                },
            )

        # -----------------------------------------------------
        # RULE 5
        # Unknown command
        # -----------------------------------------------------

        if command.operation == "UNKNOWN":

            reasons.append(
                "The command operation is not recognized."
            )

            return self._review(
                title="Unknown command requires review",
                explanation=(
                    "SafeShell cannot confidently determine "
                    "what this command will do."
                ),
                reasons=reasons,
                safer_action=(
                    "Explain the command or replace it "
                    "with a recognized operation."
                ),
                metadata={
                    "policy_rule": "UNKNOWN_OPERATION",
                },
            )

        # -----------------------------------------------------
        # RULE 6
        # Network operations
        # -----------------------------------------------------

        if command.network:

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="Network operation requires review",
                explanation=(
                    "The command accesses or transfers "
                    "data through the network."
                ),
                reasons=reasons,
                safer_action=(
                    "Verify the destination and the "
                    "data being transferred."
                ),
                metadata={
                    "policy_rule": "NETWORK_REVIEW",
                },
            )

        # -----------------------------------------------------
        # RULE 7
        # Elevated privilege
        # -----------------------------------------------------

        if command.privilege == "ELEVATED":

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="Elevated privilege requires review",
                explanation=(
                    "The command requests administrative "
                    "privileges."
                ),
                reasons=reasons,
                safer_action=(
                    "Use normal privileges if possible."
                ),
                metadata={
                    "policy_rule": "ELEVATED_PRIVILEGE",
                },
            )

        # -----------------------------------------------------
        # RULE 8
        # Destructive operations
        # -----------------------------------------------------

        if command.destructive:

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="Destructive operation requires confirmation",
                explanation=(
                    "The command will remove filesystem data."
                ),
                reasons=reasons,
                safer_action=(
                    "Verify the exact target before "
                    "confirming deletion."
                ),
                metadata={
                    "policy_rule": "DESTRUCTIVE_OPERATION",
                },
            )

        # -----------------------------------------------------
        # RULE 9
        # Wildcard + modification
        # -----------------------------------------------------

        if (
            command.uses_wildcard
            and command.modifies_files
        ):

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="Wildcard modification requires review",
                explanation=(
                    "A wildcard may cause the command "
                    "to affect multiple files."
                ),
                reasons=reasons,
                safer_action=(
                    "Replace the wildcard with an "
                    "explicit target list."
                ),
                metadata={
                    "policy_rule": "WILDCARD_MODIFICATION",
                },
            )

        # -----------------------------------------------------
        # RULE 10
        # Command chaining
        # -----------------------------------------------------

        if command.uses_command_chaining:

            reasons.extend(
                risk.reasons
            )

            return self._review(
                title="Command chain requires review",
                explanation=(
                    "Multiple commands may execute together, "
                    "making the overall effect harder to verify."
                ),
                reasons=reasons,
                safer_action=(
                    "Run one verified command at a time."
                ),
                metadata={
                    "policy_rule": "COMMAND_CHAIN",
                },
            )

        # -----------------------------------------------------
        # RULE 11
        # Safe
        # -----------------------------------------------------

        return self._allow(
            reasons=[
                "Intent and command operations match.",
                "Command target is within the intended scope.",
                "No blocking policy violations detected.",
            ],
            metadata={
                "policy_rule": "SAFE_OPERATION",
            },
        )

    # =========================================================
    # ALLOW
    # =========================================================

    @staticmethod
    def _allow(
        reasons: List[str],
        metadata: Dict[str, str],
    ) -> PolicyDecision:

        return PolicyDecision(
            decision="ALLOW",
            confidence=95,
            severity="LOW",
            title="Command appears safe",
            explanation=(
                "The command matches the user's intent "
                "and does not violate the current safety policy."
            ),
            reasons=reasons,
            safer_action=(
                "Command may proceed under the current policy."
            ),
            metadata=metadata,
        )

    # =========================================================
    # REVIEW
    # =========================================================

    @staticmethod
    def _review(
        title: str,
        explanation: str,
        reasons: List[str],
        safer_action: str,
        metadata: Dict[str, str],
    ) -> PolicyDecision:

        return PolicyDecision(
            decision="REVIEW",
            confidence=75,
            severity="HIGH",
            title=title,
            explanation=explanation,
            reasons=reasons,
            safer_action=safer_action,
            metadata=metadata,
        )

    # =========================================================
    # BLOCK
    # =========================================================

    @staticmethod
    def _block(
        title: str,
        explanation: str,
        reasons: List[str],
        safer_action: str,
        metadata: Dict[str, str],
    ) -> PolicyDecision:

        return PolicyDecision(
            decision="BLOCK",
            confidence=98,
            severity="CRITICAL",
            title=title,
            explanation=explanation,
            reasons=reasons,
            safer_action=safer_action,
            metadata=metadata,
        )


# =============================================================
# Standalone test
# =============================================================

if __name__ == "__main__":

    from ..intent.intent_engine import (
        IntentEngine,
    )

    from ..intent.intent_contract import (
        IntentContractBuilder,
    )

    from ..parser.command_parser import (
        LinuxCommandParser,
    )

    from ..risk.risk_engine import (
        RiskEngine,
    )

    from ..alignment.alignment_engine import (
        IntentCommandAligner,
    )

    intent_engine = IntentEngine()

    contract_builder = (
        IntentContractBuilder()
    )

    parser = LinuxCommandParser()

    risk_engine = RiskEngine()

    aligner = IntentCommandAligner()

    policy = PolicyEngine()

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

        (
            "I want to view files",
            "unknown-command /tmp/test",
        ),
    ]

    print("=" * 70)
    print(
        "SafeShell AI - Policy Engine Test"
    )
    print("=" * 70)

    for goal, command in test_cases:

        # -----------------------------------------------------
        # Intent
        # -----------------------------------------------------

        intent = intent_engine.classify(
            goal
        )

        # -----------------------------------------------------
        # Contract
        # -----------------------------------------------------

        contract = contract_builder.build(
            goal,
            intent,
        )

        # -----------------------------------------------------
        # Command
        # -----------------------------------------------------

        analysis = parser.parse(
            command
        )

        # -----------------------------------------------------
        # Risk
        # -----------------------------------------------------

        risk = risk_engine.assess(
            analysis
        )

        # -----------------------------------------------------
        # Alignment
        # -----------------------------------------------------

        alignment = aligner.align(
            contract,
            analysis,
        )

        # -----------------------------------------------------
        # Final policy
        # -----------------------------------------------------

        decision = policy.decide(
            contract=contract,
            command=analysis,
            risk=risk,
            alignment=alignment,
        )

        print()
        print("USER:")
        print(goal)

        print()
        print("COMMAND:")
        print(command)

        print()
        print("FINAL DECISION:")
        print(decision.decision)

        print()
        print("SEVERITY:")
        print(decision.severity)

        print()
        print("TITLE:")
        print(decision.title)

        print()
        print("EXPLANATION:")
        print(decision.explanation)

        print()
        print("REASONS:")

        for reason in decision.reasons:

            print(
                " -",
                reason,
            )

        print()
        print("SAFER ACTION:")
        print(decision.safer_action)

        print()
        print("POLICY RULE:")
        print(
            decision.metadata.get(
                "policy_rule",
                "UNKNOWN",
            )
        )

        print("-" * 70)