# 3-minute demo

## Demo 1 — Safe aligned command
Intent:
"I want to view files in ~/Downloads"

Command:
`ls -la ~/Downloads`

Show:
- Intent Contract
- LOW risk
- MATCH
- WITHIN_BUDGET
- ALLOW_AFTER_APPROVAL

## Demo 2 — Risky command
Intent:
"I want to delete old files in ~/Downloads"

Command:
`rm ~/Downloads/old.txt`

Show:
- DELETE operation
- risk factors
- review/block decision
- safer guidance

## Demo 3 — Privilege + sensitive target
Intent:
"I want to view system information"

Command:
`sudo cat /etc/passwd`

Show:
- elevated privilege
- sensitive path
- REVIEW/BLOCK

Closing:
"SafeShell does not merely ask whether a command is dangerous. It asks whether the command matches the user's intended action and stays within the predicted impact boundary."
