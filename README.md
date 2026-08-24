# SafeShell AI

**Intent Contract & Impact Guard for Safe Linux Command Execution**

## Problem

Linux commands provide powerful system control, but users may execute commands whose scope or impact differs from what they intended.

## Solution

SafeShell AI is a safety analysis layer that:

1. Understands the user's stated goal.
2. Converts it into an Intent Contract.
3. Parses the Linux command.
4. Calculates explainable risk factors.
5. Predicts potential impact.
6. Compares intent with command behavior.
7. Checks an Impact Budget.
8. Produces ALLOW / REVIEW / BLOCK guidance.
9. Provides safer guidance for risky cases.

## AI approach

The prototype uses an inbuilt TF-IDF + cosine-similarity NLP intent classifier. It is intentionally transparent and lightweight. A stronger open-source semantic model can replace this component in a future iteration without changing the surrounding safety architecture.

## Important safety property

The prototype performs analysis and does not expose arbitrary shell execution through the web UI. Controlled execution is a separate future module protected by policy and user approval.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000

## Test

```bash
pytest
```

## Architecture

User Goal -> Intent Engine -> Intent Contract -> Command Parser -> Risk/Impact -> Intent-Impact Alignment -> Impact Budget -> Safety Decision -> Safer Guidance

## Hackathon honesty note

All performance numbers in the final presentation must be measured from the actual test suite. Do not claim model accuracy without evaluation.
