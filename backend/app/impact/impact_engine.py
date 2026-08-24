from dataclasses import dataclass, asdict
from typing import Dict, List

from ..parser.command_parser import CommandAnalysis
from ..risk.risk_engine import RiskResult
from ..alignment.alignment_engine import AlignmentResult
from ..policy.policy_engine import PolicyDecision
from ..alternatives.alternative_engine import AlternativeResult


@dataclass
class ImpactReport:
    """
    Human-readable explanation of a SafeShell decision.
    """

    headline: str

    severity: str

    decision: str

    summary: str

    impact_level: str

    what_will_happen: List[str]

    why_it_matters: List[str]

    security_findings: List[str]

    recommended_action: str

    safer_command: str

    confidence: int

    metadata: Dict[str, str]

    def to_dict(self) -> Dict:
        return asdict(self)


class ImpactEngine:
    """
    Converts SafeShell's technical analysis into a
    human-readable security explanation.

    This layer does NOT make the security decision.
    It explains the decision already made by PolicyEngine.
    """

    # ---------------------------------------------------------
    # Main function
    # ---------------------------------------------------------

    def explain(
        self,
        command: CommandAnalysis,
        risk: RiskResult,
        alignment: AlignmentResult,
        decision: PolicyDecision,
        alternative: AlternativeResult,
    ) -> ImpactReport:

        # -----------------------------------------------------
        # Headline
        # -----------------------------------------------------

        headline = self._headline(
            decision
        )

        # -----------------------------------------------------
        # What will happen
        # -----------------------------------------------------

        what_will_happen = (
            self._what_will_happen(
                command
            )
        )

        # -----------------------------------------------------
        # Why it matters
        # -----------------------------------------------------

        why_it_matters = (
            self._why_it_matters(
                command,
                risk,
                alignment,
            )
        )

        # -----------------------------------------------------
        # Security findings
        # -----------------------------------------------------

        security_findings = (
            self._security_findings(
                command,
                risk,
                alignment,
            )
        )

        # -----------------------------------------------------
        # Summary
        # -----------------------------------------------------

        summary = self._summary(
            command,
            decision,
            alignment,
        )

        # -----------------------------------------------------
        # Impact level
        # -----------------------------------------------------

        impact_level = (
            self._impact_level(
                command,
                risk,
            )
        )

        # -----------------------------------------------------
        # Safer command
        # -----------------------------------------------------

        safer_command = ""

        if alternative.available:

            safer_command = (
                alternative.safer_command
            )

        return ImpactReport(
            headline=headline,
            severity=decision.severity,
            decision=decision.decision,
            summary=summary,
            impact_level=impact_level,
            what_will_happen=what_will_happen,
            why_it_matters=why_it_matters,
            security_findings=security_findings,
            recommended_action=(
                decision.safer_action
            ),
            safer_command=safer_command,
            confidence=decision.confidence,
            metadata={
                "risk_score": str(
                    risk.score
                ),
                "risk_severity": risk.severity,
                "alignment_score": str(
                    alignment.score
                ),
                "alignment_status": alignment.status,
                "policy_rule": decision.metadata.get(
                    "policy_rule",
                    "UNKNOWN",
                ),
            },
        )

    # =========================================================
    # Headline
    # =========================================================

    @staticmethod
    def _headline(
        decision: PolicyDecision,
    ) -> str:

        if decision.decision == "ALLOW":

            return "LOW RISK — Command appears safe"

        if decision.decision == "REVIEW":

            return "REVIEW REQUIRED — Command needs confirmation"

        return "BLOCKED — Command violates SafeShell policy"

    # =========================================================
    # What will happen
    # =========================================================

    @staticmethod
    def _what_will_happen(
        command: CommandAnalysis,
    ) -> List[str]:

        results: List[str] = []

        operation = command.operation

        if operation == "READ":

            results.append(
                "The command reads or inspects data."
            )

        elif operation == "CREATE":

            results.append(
                "The command creates filesystem data."
            )

        elif operation == "DELETE":

            results.append(
                "The command removes filesystem data."
            )

        elif operation == "COPY":

            results.append(
                "The command copies filesystem data."
            )

        elif operation == "MOVE":

            results.append(
                "The command moves or renames filesystem data."
            )

        elif operation == "PERMISSION_CHANGE":

            results.append(
                "The command changes filesystem permissions or ownership."
            )

        elif operation == "PROCESS_CONTROL":

            results.append(
                "The command controls a running process."
            )

        elif operation == "NETWORK":

            results.append(
                "The command communicates with a remote system."
            )

        elif operation == "PACKAGE_CHANGE":

            results.append(
                "The command changes installed software or packages."
            )

        elif operation == "SYSTEM_CONFIGURATION":

            results.append(
                "The command changes system configuration."
            )

        else:

            results.append(
                "SafeShell cannot confidently determine the command's operation."
            )

        # -----------------------------------------------------
        # Target
        # -----------------------------------------------------

        if command.targets:

            results.append(
                "Target(s): "
                + ", ".join(
                    command.targets
                )
            )

        # -----------------------------------------------------
        # Privilege
        # -----------------------------------------------------

        if command.privilege == "ELEVATED":

            results.append(
                "The command requests elevated administrative privileges."
            )

        # -----------------------------------------------------
        # Network
        # -----------------------------------------------------

        if command.network:

            results.append(
                "Network communication is involved."
            )

        # -----------------------------------------------------
        # Redirection
        # -----------------------------------------------------

        if command.uses_redirect:

            results.append(
                "Shell redirection can write or overwrite data."
            )

        return results

    # =========================================================
    # Why it matters
    # =========================================================

    @staticmethod
    def _why_it_matters(
        command: CommandAnalysis,
        risk: RiskResult,
        alignment: AlignmentResult,
    ) -> List[str]:

        reasons: List[str] = []

        if command.destructive:

            reasons.append(
                "The operation can permanently remove data."
            )

        if command.privilege == "ELEVATED":

            reasons.append(
                "Administrative privileges increase the potential impact."
            )

        if command.sensitive_target:

            reasons.append(
                "The command touches a sensitive system location."
            )

        if command.network:

            reasons.append(
                "Network activity can transfer or retrieve external data."
            )

        if command.uses_wildcard:

            reasons.append(
                "Wildcard expansion can affect multiple files."
            )

        if command.uses_command_chaining:

            reasons.append(
                "Command chaining can cause multiple operations to execute together."
            )

        if command.uses_redirect:

            reasons.append(
                "Redirection can create or overwrite files."
            )

        if not alignment.operation_match:

            reasons.append(
                "The command does not perform the operation requested by the user."
            )

        if not alignment.target_match:

            reasons.append(
                "The command target is outside the user's requested scope."
            )

        if not reasons:

            reasons.append(
                "No significant additional impact was detected."
            )

        return reasons

    # =========================================================
    # Security findings
    # =========================================================

    @staticmethod
    def _security_findings(
        command: CommandAnalysis,
        risk: RiskResult,
        alignment: AlignmentResult,
    ) -> List[str]:

        findings: List[str] = []

        if risk.score == 0:

            findings.append(
                "No elevated risk indicators detected."
            )

        else:

            findings.append(
                f"Risk score: {risk.score}/100."
            )

        if risk.severity:

            findings.append(
                f"Risk classification: {risk.severity}."
            )

        if alignment.score:

            findings.append(
                f"Intent alignment score: {alignment.score}/100."
            )

        if alignment.status:

            findings.append(
                f"Intent alignment status: {alignment.status}."
            )

        if command.sensitive_target:

            findings.append(
                "Sensitive filesystem target detected."
            )

        if command.privilege == "ELEVATED":

            findings.append(
                "Elevated privilege detected."
            )

        return findings

    # =========================================================
    # Summary
    # =========================================================

    @staticmethod
    def _summary(
        command: CommandAnalysis,
        decision: PolicyDecision,
        alignment: AlignmentResult,
    ) -> str:

        if decision.decision == "ALLOW":

            return (
                "The command matches the user's intent "
                "and satisfies the current SafeShell policy."
            )

        if not alignment.operation_match:

            return (
                "The command attempts a different operation "
                "from the one requested by the user."
            )

        if not alignment.target_match:

            return (
                "The command targets a location outside "
                "the user's requested scope."
            )

        if command.destructive:

            return (
                "The command can modify or permanently remove "
                "filesystem data and therefore requires confirmation."
            )

        if command.network:

            return (
                "The command performs network activity and "
                "requires verification before execution."
            )

        if command.privilege == "ELEVATED":

            return (
                "The command requests administrative privileges "
                "and requires additional authorization."
            )

        return (
            "SafeShell detected a condition that requires "
            "additional verification."
        )

    # =========================================================
    # Impact level
    # =========================================================

    @staticmethod
    def _impact_level(
        command: CommandAnalysis,
        risk: RiskResult,
    ) -> str:

        if (
            command.destructive
            and command.privilege == "ELEVATED"
        ):

            return "SYSTEM-WIDE"

        if command.sensitive_target:

            return "SYSTEM-SENSITIVE"

        if command.destructive:

            return "DATA-MODIFYING"

        if command.modifies_files:

            return "FILESYSTEM"

        if command.network:

            return "NETWORK"

        if command.privilege == "ELEVATED":

            return "PRIVILEGED"

        if risk.score >= 25:

            return "MODERATE"

        return "LOW"


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

    from ..policy.policy_engine import (
        PolicyEngine,
    )

    from ..alternatives.alternative_engine import (
        AlternativeEngine,
    )

    intent_engine = IntentEngine()

    contract_builder = (
        IntentContractBuilder()
    )

    parser = LinuxCommandParser()

    risk_engine = RiskEngine()

    aligner = IntentCommandAligner()

    policy_engine = PolicyEngine()

    alternative_engine = (
        AlternativeEngine()
    )

    impact_engine = ImpactEngine()

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
    ]

    print("=" * 70)
    print(
        "SafeShell AI - Impact Engine Test"
    )
    print("=" * 70)

    for goal, command in test_cases:

        intent = intent_engine.classify(
            goal
        )

        contract = contract_builder.build(
            goal,
            intent,
        )

        analysis = parser.parse(
            command
        )

        risk = risk_engine.assess(
            analysis
        )

        alignment = aligner.align(
            contract,
            analysis,
        )

        decision = policy_engine.decide(
            contract=contract,
            command=analysis,
            risk=risk,
            alignment=alignment,
        )

        alternative = (
            alternative_engine.suggest(
                contract=contract,
                command=analysis,
                risk=risk,
                alignment=alignment,
                decision=decision,
            )
        )

        report = impact_engine.explain(
            command=analysis,
            risk=risk,
            alignment=alignment,
            decision=decision,
            alternative=alternative,
        )

        print()
        print("USER:")
        print(goal)

        print()
        print("COMMAND:")
        print(command)

        print()
        print("HEADLINE:")
        print(report.headline)

        print()
        print("SUMMARY:")
        print(report.summary)

        print()
        print("IMPACT LEVEL:")
        print(report.impact_level)

        print()
        print("WHAT WILL HAPPEN:")

        for item in report.what_will_happen:

            print(
                " -",
                item,
            )

        print()
        print("WHY IT MATTERS:")

        for item in report.why_it_matters:

            print(
                " -",
                item,
            )

        print()
        print("SECURITY FINDINGS:")

        for item in report.security_findings:

            print(
                " -",
                item,
            )

        print()
        print("RECOMMENDED ACTION:")
        print(
            report.recommended_action
        )

        print()
        print("SAFER COMMAND:")
        print(
            report.safer_command
            or "(none)"
        )

        print()
        print("CONFIDENCE:")
        print(
            report.confidence
        )

        print("-" * 70)