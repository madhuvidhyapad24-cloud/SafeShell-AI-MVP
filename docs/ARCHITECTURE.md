# SafeShell AI Architecture

User Goal
  -> AI Intent Engine
  -> Intent Contract
  -> Linux Command Parser
  -> Risk Engine
  -> Impact Engine
  -> Intent-Impact Alignment
  -> Impact Budget
  -> Safety Policy
  -> Safer Guidance
  -> User Approval
  -> Controlled Executor (future/isolated)
  -> Post-Execution Verification (future/isolated)

## Design principle

AI is an analysis component, not an unrestricted execution authority.

## Current prototype

The current MVP implements intent classification, command parsing, risk analysis, intent alignment, impact estimation, budget checking, and a browser dashboard. It intentionally does not execute arbitrary shell commands.
