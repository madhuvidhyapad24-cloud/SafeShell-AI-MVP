from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class IntentResult:
    """
    Result produced by the SafeShell AI Intent Engine.
    """

    operation: str
    confidence: float
    evidence: List[str]
    constraints: Dict[str, str]


class IntentEngine:
    """
    Hybrid intent engine.

    Layer 1:
        Deterministic detection of explicit safety-sensitive
        operations.

    Layer 2:
        TF-IDF semantic matching for less explicit language.

    The engine NEVER executes commands.
    """

    EXAMPLES: Dict[str, List[str]] = {

        "READ": [
            "view files",
            "view a file",
            "list files",
            "show files",
            "read a file",
            "inspect a directory",
            "inspect files",
            "check folder contents",
            "see files",
            "look at files",
            "view directory",
            "read directory",
        ],

        "CREATE": [
            "create a file",
            "create a folder",
            "create a directory",
            "make a file",
            "make a folder",
            "make a directory",
            "make a new file",
            "make a new folder",
            "make a new directory",
        ],

        "DELETE": [
            "delete a file",
            "delete files",
            "remove a file",
            "remove files",
            "erase a file",
            "erase files",
            "destroy a file",
            "destroy files",
        ],

        "COPY": [
            "copy a file",
            "copy files",
            "duplicate a file",
            "duplicate files",
            "make a copy",
        ],

        "MOVE": [
            "move a file",
            "move files",
            "rename a file",
            "rename files",
            "change a file location",
        ],

        "PERMISSION_CHANGE": [
            "change file permissions",
            "modify file permissions",
            "change permissions",
            "modify permissions",
            "change ownership",
            "change file ownership",
            "make a file executable",
        ],

        "PROCESS_CONTROL": [
            "stop a process",
            "stop the process",
            "stop a running process",
            "terminate a process",
            "terminate the process",
            "terminate a running process",
            "kill a process",
            "kill the process",
            "kill a running process",
            "stop a running program",
        ],

        "NETWORK": [
            "download a file",
            "download something",
            "upload a file",
            "upload something",
            "connect to a server",
            "connect to a remote server",
            "send data",
            "access a remote server",
        ],

        "PACKAGE_CHANGE": [
            "install a package",
            "install software",
            "install an application",
            "remove a package",
            "uninstall a package",
            "uninstall software",
            "update software",
            "update packages",
        ],

        "SYSTEM_CONFIGURATION": [
            "change system configuration",
            "modify system configuration",
            "change system settings",
            "modify system settings",
            "configure the operating system",
            "configure linux",
        ],
    }

    def __init__(self) -> None:

        self._texts: List[str] = []
        self._labels: List[str] = []

        for label, examples in self.EXAMPLES.items():

            for example in examples:
                self._texts.append(example)
                self._labels.append(label)

        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
        )

        self._matrix = self._vectorizer.fit_transform(
            self._texts
        )

    def classify(self, user_goal: str) -> IntentResult:
        """
        Classify a natural-language user goal.

        Explicit safety-sensitive language has priority.
        Semantic matching is the fallback.
        """

        cleaned = user_goal.strip()

        # Empty input
        if not cleaned:
            return IntentResult(
                operation="UNKNOWN",
                confidence=0.0,
                evidence=[
                    "No user intent was provided."
                ],
                constraints=self._constraints(
                    "UNKNOWN"
                ),
            )

        # -----------------------------------------------------
        # Stage 1: explicit intent detection
        # -----------------------------------------------------

        explicit_operation, explicit_evidence = (
            self._explicit_operation(cleaned)
        )

        if explicit_operation is not None:

            return IntentResult(
                operation=explicit_operation,
                confidence=1.0,
                evidence=[
                    "Explicit intent phrase detected.",
                    *explicit_evidence,
                ],
                constraints=self._constraints(
                    explicit_operation
                ),
            )

        # -----------------------------------------------------
        # Stage 2: semantic fallback
        # -----------------------------------------------------

        vector = self._vectorizer.transform(
            [cleaned]
        )

        scores = cosine_similarity(
            vector,
            self._matrix,
        )[0]

        best_index = int(scores.argmax())

        raw_confidence = float(
            scores[best_index]
        )

        operation = self._labels[
            best_index
        ]

        # Low confidence must never silently become trusted.
        if raw_confidence < 0.20:
            operation = "UNKNOWN"

        confidence = round(
            raw_confidence,
            3,
        )

        evidence = [
            f"Semantic operation candidate: {operation}",
            f"Semantic similarity score: {confidence}",
        ]

        if confidence < 0.20:
            evidence.append(
                "Confidence is low; "
                "safety policy should require review."
            )

        return IntentResult(
            operation=operation,
            confidence=confidence,
            evidence=evidence,
            constraints=self._constraints(
                operation
            ),
        )

    @staticmethod
    def _contains_phrase(
        text: str,
        phrase: str,
    ) -> bool:
        """
        Safely match a complete word or phrase.

        This prevents:

            download

        from incorrectly matching:

            Downloads

        It also handles punctuation and normal word boundaries.
        """

        pattern = (
            r"(?<!\w)"
            + re.escape(
                phrase.lower()
            )
            + r"(?!\w)"
        )

        return re.search(
            pattern,
            text,
        ) is not None

    def _explicit_operation(
        self,
        user_goal: str,
    ) -> Tuple[
        Optional[str],
        List[str],
    ]:
        """
        Detect explicit operations.

        More specific operations are checked before generic
        operations such as DELETE and READ.
        """

        text = user_goal.lower()

        # -----------------------------------------------------
        # 1. Package changes
        # -----------------------------------------------------

        package_phrases = [
            "install a package",
            "install package",
            "install software",
            "install an application",
            "remove a package",
            "remove package",
            "uninstall a package",
            "uninstall package",
            "uninstall software",
            "update software",
            "update packages",
        ]

        for phrase in package_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "PACKAGE_CHANGE",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 2. Permission changes
        # -----------------------------------------------------

        permission_phrases = [
            "change file permissions",
            "modify file permissions",
            "change permissions",
            "modify permissions",
            "change ownership",
            "change file ownership",
            "make a file executable",
        ]

        for phrase in permission_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "PERMISSION_CHANGE",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 3. Process control
        # -----------------------------------------------------

        process_phrases = [
            "kill a process",
            "kill the process",
            "kill process",
            "kill a running process",
            "stop a process",
            "stop the process",
            "stop process",
            "stop a running process",
            "terminate a process",
            "terminate the process",
            "terminate process",
            "terminate a running process",
            "stop a running program",
        ]

        for phrase in process_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "PROCESS_CONTROL",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 4. Network
        # -----------------------------------------------------

        network_phrases = [
            "download a file",
            "download something",
            "upload a file",
            "upload something",
            "connect to a server",
            "connect to the server",
            "connect to a remote server",
            "send data",
            "access a remote server",
        ]

        for phrase in network_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "NETWORK",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 5. System configuration
        # -----------------------------------------------------

        configuration_phrases = [
            "change system configuration",
            "modify system configuration",
            "change system settings",
            "modify system settings",
            "configure the operating system",
            "configure linux",
        ]

        for phrase in configuration_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "SYSTEM_CONFIGURATION",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 6. Delete
        # -----------------------------------------------------

        delete_phrases = [
            "delete",
            "remove",
            "erase",
            "destroy",
        ]

        for phrase in delete_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "DELETE",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 7. Create
        # -----------------------------------------------------

        create_phrases = [
            "create a file",
            "create a folder",
            "create a directory",
            "make a file",
            "make a folder",
            "make a directory",
            "make a new file",
            "make a new folder",
            "make a new directory",
        ]

        for phrase in create_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "CREATE",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 8. Copy
        # -----------------------------------------------------

        copy_phrases = [
            "copy a file",
            "copy files",
            "duplicate a file",
            "duplicate files",
            "make a copy",
        ]

        for phrase in copy_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "COPY",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 9. Move / Rename
        # -----------------------------------------------------

        move_phrases = [
            "move a file",
            "move files",
            "rename a file",
            "rename files",
            "change a file location",
        ]

        for phrase in move_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "MOVE",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # -----------------------------------------------------
        # 10. Read
        # -----------------------------------------------------

        read_phrases = [
            "view files",
            "view a file",
            "list files",
            "show files",
            "read a file",
            "read files",
            "inspect a directory",
            "inspect files",
            "check folder contents",
            "see files",
            "look at files",
            "view directory",
            "read directory",
        ]

        for phrase in read_phrases:

            if self._contains_phrase(
                text,
                phrase,
            ):
                return (
                    "READ",
                    [
                        f"Matched explicit phrase: '{phrase}'"
                    ],
                )

        # Nothing explicit found
        return None, []

    @staticmethod
    def _constraints(
        operation: str,
    ) -> Dict[str, str]:
        """
        Generate preliminary constraints.

        These are NOT the final security decision.
        The Policy Engine will make the final decision later.
        """

        # READ
        if operation == "READ":

            return {
                "filesystem": "TARGET_ONLY",
                "modification": "FORBIDDEN",
                "network": "FORBIDDEN",
                "privilege": "NORMAL",
            }

        # File operations
        if operation in {
            "CREATE",
            "DELETE",
            "COPY",
            "MOVE",
            "PERMISSION_CHANGE",
        }:

            return {
                "filesystem": "TARGET_ONLY",
                "modification": "ALLOWED_FOR_INTENT",
                "network": "FORBIDDEN",
                "privilege": "NORMAL",
            }

        # Network
        if operation == "NETWORK":

            return {
                "filesystem": "TARGET_ONLY",
                "modification": "MINIMAL",
                "network": "REQUIRES_REVIEW",
                "privilege": "NORMAL",
            }

        # Process
        if operation == "PROCESS_CONTROL":

            return {
                "filesystem": "NOT_REQUIRED",
                "modification": "PROCESS_ONLY",
                "network": "FORBIDDEN",
                "privilege": "REQUIRES_REVIEW",
            }

        # Package management
        if operation == "PACKAGE_CHANGE":

            return {
                "filesystem": "SYSTEM_PACKAGE_SCOPE",
                "modification": "SYSTEM_CHANGE",
                "network": "REQUIRES_REVIEW",
                "privilege": "REQUIRES_REVIEW",
            }

        # System configuration
        if operation == "SYSTEM_CONFIGURATION":

            return {
                "filesystem": "SYSTEM_SCOPE",
                "modification": "SYSTEM_CHANGE",
                "network": "FORBIDDEN",
                "privilege": "REQUIRES_REVIEW",
            }

        # Unknown
        return {
            "filesystem": "UNKNOWN",
            "modification": "UNKNOWN",
            "network": "UNKNOWN",
            "privilege": "REVIEW_REQUIRED",
        }


# =============================================================
# Standalone test
# =============================================================

if __name__ == "__main__":

    engine = IntentEngine()

    test_cases = [

        "I want to view files in my Downloads folder",

        "I want to delete an old file",

        "I need to make a new directory",

        "I want to stop a running process",

        "I want to download a file",

        "I want to install a package",

        "I want to remove a package",

        "I want to change file permissions",

        "I want to copy a file",

        "I want to rename a file",

        "I don't know what this command does",
    ]

    print("=" * 70)
    print("SafeShell AI - Intent Engine Test")
    print("=" * 70)

    for example in test_cases:

        result = engine.classify(
            example
        )

        print()
        print("USER:")
        print(example)

        print()
        print("OPERATION:")
        print(result.operation)

        print()
        print("CONFIDENCE:")
        print(result.confidence)

        print()
        print("CONSTRAINTS:")
        print(result.constraints)

        print()
        print("EVIDENCE:")

        for evidence in result.evidence:
            print(" -", evidence)

        print("-" * 70)