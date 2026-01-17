# Apple Policy Lint (Swift AST)
Policy-sensitive API checks in pull requests (before App Store review).

Apple Policy Lint is a GitHub Action that scans Swift code using a real AST (tree-sitter),
detects Apple policy-sensitive APIs (example: Required Reason APIs), and posts a clean PR report
with file/line/rule + remediation guidance.

**Goal:** catch policy mistakes early when fixes are cheap.

> Not affiliated with Apple.

---

## Why this exists
Teams usually discover Apple privacy/policy issues:
- late (right before submission),
- inconsistently (tribal knowledge + checklists),
- and expensively (review churn, release delays).

This action makes policy checks:
- deterministic
- versioned
- and reviewable in PRs

Think "policy-as-code", not "wiki-as-policy".

---

## What you get
- ✅ AST-based scanning (no regex)
- ✅ PR comment report (clean, readable)
- ✅ Optional GitHub annotations (`::error file=...`)
- ✅ Optional merge gate (fail workflow when issues exist)
- ✅ JSON output for downstream automation

---

## Example PR report

<!-- swift-policy-bot -->
## Apple Policy Lint (Swift AST)

Found **1** potential policy-relevant API usages.

| Category | Symbol | File | Line | Rule |
|---|---|---|---:|---|
| Required Reason API: Active Keyboards | `activeInputModes` | `TestPipeline/PolicyTrigger.swift` | 5 | `APPLE_REQUIRED_REASON_ACTIVE_KEYBOARDS` |

### Details
- **activeInputModes** in `TestPipeline/PolicyTrigger.swift`:5:25  
  Rule: `APPLE_REQUIRED_REASON_ACTIVE_KEYBOARDS`  
  Potential Active Keyboards API usage detected. If this is real usage, ensure `PrivacyInfo.xcprivacy`
  declares `NSPrivacyAccessedAPITypes` with an approved reason. (symbol: `activeInputModes`)

---

## Quickstart (GitHub Action)

### 1) Add to your workflow
Create `.github/workflows/apple-policy-lint.yml`:

```yaml
name: Apple Policy Lint

on:
  pull_request:
    branches: [ main ]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      # If action.yml is at repo root:
      - uses: skprasadu/apple-policy-lint@v0.1.0
        with:
          root: "."
          comment: "true"
          fail_on_issues: "true"
          github_annotations: "true"