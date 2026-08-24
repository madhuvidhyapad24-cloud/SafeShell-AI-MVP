from dataclasses import dataclass, asdict
from typing import Dict, List

from ..parser.command_parser import CommandAnalysis


@dataclass
class RiskResult:
    """
    Result produced by the SafeShell Risk Engine.
    """

    score: int
    severity: str

    reasons: List[str]

    recommended_action: str

    dimensions: Dict[str, int]

    def to_dict(self) -> Dict:
        return asdict(self)


class RiskEngine:
    """
    Explainable rule-based risk engine.

    The engine consumes CommandAnalysis and produces:

        risk score
        severity
        reasons
        recommended action
        risk dimensions

    It does NOT execute commands.
    """

    # ---------------------------------------------------------
    # Score limits
    # ---------------------------------------------------------

    MAX_SCORE = 100

    # ---------------------------------------------------------
    # Calculate risk
    # ---------------------------------------------------------

    def assess(
        self,
        analysis: CommandAnalysis,
    ) -> RiskResult:

        score = 0

        reasons: List[str] = []

        dimensions: Dict[str, int] = {
            "destructive": 0,
            "privilege": 0,
            "sensitive_target": 0,
            "network": 0,
            "wildcard": 0,
            "pipeline": 0,
            "redirection": 0,
            "chaining": 0,
            "unknown": 0,
        }

        # -----------------------------------------------------
        # 1. Destructive operation
        # -----------------------------------------------------

        if analysis.destructive:

            points = 35

            score += points

            dimensions["destructive"] = points

            reasons.append(
                "Destructive filesystem operation detected."
            )

        # -----------------------------------------------------
        # 2. Elevated privilege
        # -----------------------------------------------------

        if analysis.privilege == "ELEVATED":

            points = 30

            score += points

            dimensions["privilege"] = points

            reasons.append(
                "Command requests elevated privilege."
            )

        # -----------------------------------------------------
        # 3. Sensitive target
        # -----------------------------------------------------

        if analysis.sensitive_target:

            points = 25

            score += points

            dimensions["sensitive_target"] = points

            reasons.append(
                "Command targets a sensitive system location."
            )

        # -----------------------------------------------------
        # 4. Network operation
        # -----------------------------------------------------

        if analysis.network:

            points = 15

            score += points

            dimensions["network"] = points

            reasons.append(
                "Command performs or enables network activity."
            )

        # -----------------------------------------------------
        # 5. Wildcards
        # -----------------------------------------------------

        if analysis.uses_wildcard:

            points = 10

            score += points

            dimensions["wildcard"] = points

            reasons.append(
                "Wildcard expansion may affect multiple targets."
            )

        # -----------------------------------------------------
        # 6. Pipeline
        # -----------------------------------------------------

        if analysis.uses_pipe:

            points = 5

            score += points

            dimensions["pipeline"] = points

            reasons.append(
                "Pipeline detected; command behavior spans multiple stages."
            )

        # -----------------------------------------------------
        # 7. Redirection
        # -----------------------------------------------------

        if analysis.uses_redirect:

            points = 15

            score += points

            dimensions["redirection"] = points

            reasons.append(
                "Shell redirection can write or overwrite data."
            )

        # -----------------------------------------------------
        # 8. Command chaining
        # -----------------------------------------------------

        if analysis.uses_command_chaining:

            points = 15

            score += points

            dimensions["chaining"] = points

            reasons.append(
                "Multiple commands may execute as a chain."
            )

        # -----------------------------------------------------
        # 9. Unknown command
        # -----------------------------------------------------

        if analysis.operation == "UNKNOWN":

            points = 20

            score += points

            dimensions["unknown"] = points

            reasons.append(
                "Command operation is unknown to the analyzer."
            )

        # -----------------------------------------------------
        # Cap score
        # -----------------------------------------------------

        score = min(
            score,
            self.MAX_SCORE,
        )

        # -----------------------------------------------------
        # Severity
        # -----------------------------------------------------

        severity = self._severity(
            score
        )

        # -----------------------------------------------------
        # Recommended action
        # -----------------------------------------------------

        recommended_action = (
            self._recommended_action(
                score,
                analysis,
            )
        )

        # -----------------------------------------------------
        # Safe explanation
        # -----------------------------------------------------

        if not reasons:

            reasons.append(
                "No significant risk indicators were detected."
            )

        return RiskResult(
            score=score,
            severity=severity,
            reasons=reasons,
            recommended_action=recommended_action,
            dimensions=dimensions,
        )

    # ---------------------------------------------------------
    # Severity
    # ---------------------------------------------------------

    @staticmethod
    def _severity(
        score: int,
    ) -> str:

        if score >= 75:

            return "CRITICAL"

        if score >= 50:

            return "HIGH"

        if score >= 25:

            return "MEDIUM"

        return "LOW"

    # ---------------------------------------------------------
    # Recommended action
    # ---------------------------------------------------------

    @staticmethod
    def _recommended_action(
        score: int,
        analysis: CommandAnalysis,
    ) -> str:

        # Highest-risk situations require blocking/review.
        if score >= 75:

            return "BLOCK"

        if score >= 50:

            return "REVIEW"

        # Unknown operations should not execute automatically.
        if analysis.operation == "UNKNOWN":

            return "REVIEW"

        # Elevated privilege requires additional policy review.
        if analysis.privilege == "ELEVATED":

            return "REVIEW"

        # Network operations require policy review.
        if analysis.network:

            return "REVIEW"

        return "ALLOW"


# =============================================================
# Standalone test
# =============================================================

if __name__ == "__main__":

    from ..parser.command_parser import (
        LinuxCommandParser
    )

    parser = LinuxCommandParser()

    engine = RiskEngine()

    test_commands = [

        "ls -la ~/Downloads",

        "cat ~/Downloads/notes.txt",

        "rm ~/Downloads/old.txt",

        "sudo rm /important/file",

        "sudo cat /etc/passwd",

        "curl https://example.com",

        "ls *.txt",

        "rm file1.txt && rm file2.txt",

        "cat > output.txt",

        "unknown-command /tmp/test",
    ]

    print("=" * 70)
    print(
        "SafeShell AI - Risk Engine Test"
    )
    print("=" * 70)

    for command in test_commands:

        analysis = parser.parse(
            command
        )

        result = engine.assess(
            analysis
        )

        print()
        print("COMMAND:")
        print(command)

        print()
        print("RISK SCORE:")
        print(result.score)

        print()
        print("SEVERITY:")
        print(result.severity)

        print()
        print("ACTION:")
        print(result.recommended_action)

        print()
        print("REASONS:")

        for reason in result.reasons:

            print(
                " -",
                reason
            )

        print()
        print("DIMENSIONS:")

        for key, value in result.dimensions.items():

            if value > 0:

                print(
                    f" - {key}: +{value}"
                )

        print("-" * 70)