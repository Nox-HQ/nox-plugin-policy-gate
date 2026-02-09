# nox-plugin-policy-gate

**CI policy gate enforcement for secure pipelines.**

## Overview

`nox-plugin-policy-gate` scans CI/CD pipeline configurations for missing security gates, policy enforcement gaps, and insecure practices. It analyzes GitHub Actions workflows, GitLab CI configurations, Jenkinsfiles, CircleCI configs, and Bitbucket Pipelines to verify that security scanning steps, branch protection, deployment approval gates, and dependency audits are in place.

CI/CD pipelines are the gatekeepers of production. If a pipeline lacks a security scanning step, vulnerabilities flow through unchecked. If production deployments have no approval gate, a compromised developer account can push malicious code directly to production. If third-party GitHub Actions are pinned to `@main` instead of a SHA, a supply chain attack on the action repository compromises every pipeline that uses it. This plugin catches these CI/CD security anti-patterns by analyzing pipeline configuration files, ensuring that the path to production includes the security controls your organization requires.

The plugin belongs to the **Policy Governance** track and operates with a passive risk class. It performs read-only analysis of CI configuration files without executing any pipelines, making network requests, or modifying any files.

## Use Cases

### Enforcing Security Scanning in All CI Pipelines

An organization mandates that every CI pipeline must include at least one security scanning step (SAST, DAST, or secrets scanning). The policy-gate plugin scans all CI configuration files and flags any pipeline that lacks references to tools like Semgrep, CodeQL, SonarQube, OWASP ZAP, Gitleaks, or TruffleHog. This provides a clear remediation target for each team.

### Preventing Direct-to-Production Deployments

A regulated environment requires that all production deployments go through a manual approval gate. The policy-gate plugin detects production deployment steps (`deploy-to-prod`, `push-to-production`) and verifies that they are gated by approval requirements, environment protection rules, or manual triggers. Ungated production deployments are flagged with high severity.

### Auditing GitHub Actions for Supply Chain Risks

A security team needs to verify that all third-party GitHub Actions are pinned to specific SHA commits rather than branch names like `@main` or `@master`. The policy-gate plugin detects unpinned third-party actions (excluding first-party `actions/*` actions and those pinned to full semver tags) and flags each one, reducing the risk of supply chain attacks through compromised action repositories.

### Ensuring Dependency Audit Steps Exist

A team wants to verify that every CI pipeline includes a dependency audit step -- `npm audit`, `pip audit`, `govulncheck`, `cargo audit`, or integration with Dependabot/Renovate. The policy-gate plugin checks each CI configuration for these patterns and flags pipelines where dependency auditing is absent.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/nox-hq/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-policy-gate
   ```

2. **Create a test project with a minimal CI pipeline**

   ```bash
   mkdir -p demo-policy-gate/.github/workflows && cd demo-policy-gate
   ```

   Create `.github/workflows/ci.yml`:

   ```yaml
   name: CI
   on: [push, pull_request]

   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: some-org/risky-action@main
         - run: go build ./...

     deploy-to-prod:
       runs-on: ubuntu-latest
       needs: build
       steps:
         - run: |
             echo "Deploying to production..."
             password: "deploy_secret_123"
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/policy-gate .
   ```

4. **Review findings**

   ```
   POLICY-001  HIGH/HIGH   .github/workflows/ci.yml:1   No branch protection configuration detected in github-actions pipeline
   POLICY-002  MED/HIGH    .github/workflows/ci.yml:1   CI pipeline has no security scanning step (no SAST, DAST, or secrets scanning) in github-actions config
   POLICY-003  HIGH/MED    .github/workflows/ci.yml:14  Deployment to production without approval gate in github-actions pipeline
   POLICY-004  MED/MED     .github/workflows/ci.yml:1   No dependency audit step found in github-actions pipeline
   POLICY-005  MED/HIGH    .github/workflows/ci.yml:9   Third-party GitHub Action used without pinned SHA: - uses: some-org/risky-action@main
   POLICY-005  MED/HIGH    .github/workflows/ci.yml:17  Hardcoded secret detected in CI pipeline configuration

   6 findings (2 high, 4 medium)
   ```

## Rules

| Rule ID    | Description                                                              | Severity | Confidence | CWE |
|------------|--------------------------------------------------------------------------|----------|------------|-----|
| POLICY-001 | No branch protection configuration detected in CI pipeline               | HIGH     | HIGH       | --  |
| POLICY-002 | CI pipeline has no security scanning step (no SAST, DAST, or secrets scanning) | MEDIUM   | HIGH       | --  |
| POLICY-003 | Deployment to production without approval gate                           | HIGH     | MEDIUM     | --  |
| POLICY-004 | No dependency audit step found in CI pipeline                            | MEDIUM   | MEDIUM     | --  |
| POLICY-005 | Insecure CI pipeline practices (hardcoded secrets, root execution, unpinned actions) | MEDIUM   | HIGH       | --  |

### POLICY-005 Sub-Categories

| Practice           | Detection Pattern                                                     |
|--------------------|-----------------------------------------------------------------------|
| Hardcoded Secrets  | `password`, `secret`, `token`, `api_key` with literal string values   |
| Root Execution     | `runs-on:.*root`, `user: root`, `--privileged`                        |
| Unpinned Actions   | Third-party GitHub Actions pinned to `@main`, `@master`, or `@latest` (excludes `actions/*`, SHA pins, and full semver) |

### Security Scanning Tools Detected (POLICY-002)

| Category       | Tools Detected                                                         |
|----------------|------------------------------------------------------------------------|
| SAST           | Semgrep, SonarQube, CodeQL, Bandit, Gosec, Brakeman, SpotBugs, Checkmarx, Fortify, Snyk Code |
| DAST           | OWASP ZAP, Burp, Nikto, Nuclei, Arachni                               |
| Secrets        | TruffleHog, Gitleaks, detect-secrets, git-secrets, Talisman, Whispers  |

## Supported Languages / File Types

| CI System        | Configuration Files                                          |
|------------------|--------------------------------------------------------------|
| GitHub Actions   | `.github/workflows/*.yml`, `.github/workflows/*.yaml`        |
| GitLab CI        | `.gitlab-ci.yml`, `.gitlab-ci.yaml`                          |
| Jenkins          | `Jenkinsfile`                                                |
| CircleCI         | `.circleci/config.yml`, `.circleci/config.yaml`              |
| Bitbucket        | `bitbucket-pipelines.yml`, `bitbucket-pipelines.yaml`        |

## Configuration

The plugin uses Nox's standard configuration. No additional configuration is required.

```yaml
# .nox.yaml (optional)
plugins:
  nox/policy-gate:
    enabled: true
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-policy-gate
```

### Standalone

```bash
go install github.com/nox-hq/nox-plugin-policy-gate@latest
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-policy-gate.git
cd nox-plugin-policy-gate
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Build Docker image
docker build -t nox-plugin-policy-gate .

# Clean build artifacts
make clean
```

## Architecture

The plugin operates as a Nox plugin server communicating over stdio using the Nox Plugin SDK. The scan follows a two-phase approach:

1. **CI File Discovery** -- Searches for CI configuration files at known locations using exact paths and glob patterns. Each discovered file is tagged with its CI system type (github-actions, gitlab-ci, jenkins, circleci, bitbucket).
2. **Per-File Policy Checks** -- Each CI configuration file is read into memory and analyzed by five check functions:
   - **Branch Protection** (POLICY-001): Searches for review requirements, required status checks, and approval configuration patterns.
   - **Security Scanning** (POLICY-002): Checks whether any SAST, DAST, or secrets scanning tool is referenced. The check passes if any one scanning category is present.
   - **Deployment Approval** (POLICY-003): Only fires when a production deployment step is detected. Checks for approval gates, manual triggers, or environment protection rules. Reports the specific line number of the ungated deployment step.
   - **Dependency Audit** (POLICY-004): Searches for dependency audit commands or tool references across all ecosystems.
   - **Insecure Practices** (POLICY-005): Performs line-by-line analysis to detect hardcoded secrets, root execution, and unpinned third-party GitHub Actions. Actions pinned to SHA commits or full semver tags are exempted. First-party `actions/*` actions are also exempted.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-policy-gate).

When adding new policy checks:
1. Define compiled regex patterns for the new policy.
2. Implement a `check*` function that reads the CI file content and emits findings.
3. Call the new check function from `scanCIFile`.
4. Add test cases with sample CI configuration files.

## License

Apache-2.0
