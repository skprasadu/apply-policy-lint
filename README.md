# Apple Policy Lint (Swift AST)

**Deterministic policy enforcement via GitHub Actions for modern codebases.**

Apple Policy Lint scans Swift code using a real AST (tree-sitter) and detects Apple policy-sensitive APIs
(e.g., Required Reason APIs). It posts a clean PR report (file/line/rule + remediation guidance) and can gate merges.

> Not affiliated with Apple.

---

## What you get
- AST-based scanning (not regex)
- PR comment report (readable + reviewable)
- Optional GitHub annotations (`::error file=...`)
- Optional merge gate (fail workflow when issues exist)
- Baseline support: fail only on **new** findings

---

## Quickstart (recommended onboarding)

### Step 0 — Enable workflow permissions (required for baseline PR)
Repo → **Settings → Actions → General**
- Workflow permissions: **Read and write**
- Enable: **Allow GitHub Actions to create and approve pull requests**

---

### Step 1 — Add config file
Create `.p2i/config.json`:

```json
{
  "ignore_paths": [".git",".github","Pods","Carthage",".build","build","DerivedData","vendor"],
  "ignore_rules": []
}
```

### Step 2 — Create baseline workflow

Add .github/workflows/apple-policy-baseline.yml (baseline PR will be created):
- Runs full scan
- Writes .p2i/baseline.json
- Opens PR: chore(policy): update apple-policy-lint baseline

(Use the onboarding pack from p2i.ai docs / customer pack repo.)

Run it once from Actions → workflow_dispatch → merge baseline PR.

### Step 3 — Add PR lint workflow

Add .github/workflows/apple-policy-lint.yml:
- Runs on PRs
- Scans only changed Swift files (diff mode)
- Fails only on findings not present in baseline

### Inputs

Key inputs most teams use:
- scan: full or diff
- config_path: .p2i/config.json
- baseline_json: .p2i/baseline.json
- only_new: "true" (recommended)
- fail_on_issues: "true" (recommended)

### Outputs
- count: number of findings


### Docs / onboarding

Full onboarding docs: https://p2i.ai (Apple Policy Lint section)

