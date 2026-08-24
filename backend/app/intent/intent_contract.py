from dataclasses import dataclass, asdict
from typing import Dict
import re

from .intent_engine import IntentResult


@dataclass
class IntentContract:
    """Formal safety boundary derived from the user's intent."""

    goal: str
    operation: str
    target: str
    confidence: float

    modification: str
    network: str
    privilege: str
    filesystem_scope: str

    def to_dict(self) -> Dict:
        return asdict(self)


class IntentContractBuilder:
    """Convert an IntentResult into a structured safety contract."""

    def build(
        self,
        user_goal: str,
        intent_result: IntentResult,
    ) -> IntentContract:

        target = self._extract_target(user_goal)
        constraints = intent_result.constraints

        return IntentContract(
            goal=user_goal.strip(),
            operation=intent_result.operation,
            target=target,
            confidence=intent_result.confidence,
            modification=constraints.get(
                "modification",
                "UNKNOWN",
            ),
            network=constraints.get(
                "network",
                "UNKNOWN",
            ),
            privilege=constraints.get(
                "privilege",
                "REVIEW_REQUIRED",
            ),
            filesystem_scope=constraints.get(
                "filesystem",
                "UNKNOWN",
            ),
        )

    @staticmethod
    def _extract_target(user_goal: str) -> str:
        """
        Extract an explicit Linux-style path.

        If no path is present, do not invent one.
        """

        patterns = [
            r"(~[/\\][^\s,]+)",
            r"(/[^\s,]+)",
            r"(\.{1,2}[/\\][^\s,]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, user_goal)

            if match:
                return match.group(1)

        return "UNSPECIFIED"


if __name__ == "__main__":
    from .intent_engine import IntentEngine

    engine = IntentEngine()
    builder = IntentContractBuilder()

    examples = [
        "I want to view files in ~/Downloads",
        "I want to delete an old file in ~/Downloads",
        "I want to create a folder in ~/Projects",
        "I want to download a file",
    ]

    for goal in examples:

        intent = engine.classify(goal)

        contract = builder.build(
            goal,
            intent,
        )

        print("\nUSER GOAL:")
        print(goal)

        print("\nINTENT CONTRACT:")

        for key, value in contract.to_dict().items():
            print(f"{key}: {value}")