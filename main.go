package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// --- Compiled regex patterns ---

var (
	// POLICY-001: Branch protection indicators in CI config.
	reRequiredReviewers = regexp.MustCompile(`(?i)(required_pull_request_reviews|required_approving_review_count|required_status_checks|branch_protection|pull_request_reviews|reviewers|approvals)`)

	// POLICY-002: Security scanning steps.
	reSASTStep    = regexp.MustCompile(`(?i)(sast|semgrep|sonarqube|sonar-scanner|codeql|bandit|gosec|brakeman|spotbugs|checkmarx|fortify|snyk\s+code|snyk\s+test)`)
	reDASTStep    = regexp.MustCompile(`(?i)(dast|zap|owasp.*zap|burp|nikto|nuclei|arachni)`)
	reSecretsStep = regexp.MustCompile(`(?i)(secret.?scan|trufflehog|gitleaks|detect-secrets|git-secrets|talisman|whispers)`)

	// POLICY-003: Deployment approval gates.
	reDeployProd    = regexp.MustCompile(`(?i)(deploy.*prod|production.*deploy|push.*prod|release.*prod)`)
	reApprovalGate  = regexp.MustCompile(`(?i)(environment:.*production|required_reviewers|manual_approval|approval|needs:\s*\[.*approval|wait_for_approval|gate|human.*review)`)
	reManualTrigger = regexp.MustCompile(`(?i)(workflow_dispatch|when:\s*manual|manual)`)

	// POLICY-004: Dependency audit step.
	reDepAudit = regexp.MustCompile(`(?i)(npm\s+audit|yarn\s+audit|pip\s+audit|pip-audit|safety\s+check|govulncheck|cargo\s+audit|bundler-audit|snyk\s+test|dependency.?check|dependabot|renovate|ossf.?scorecard)`)

	// POLICY-005: Insecure CI practices.
	reHardcodedSecret    = regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey)\s*[:=]\s*['"][^${\s]{4,}['"]`)
	reRunAsRoot          = regexp.MustCompile(`(?i)(runs-on:.*root|user:\s*root|--privileged|docker.*--privileged)`)
	reUnpinnedAction     = regexp.MustCompile(`uses:\s+([^@\s#]+)@(master|main|latest|v\d+)\s*$`)
	reUnpinnedActionSHA  = regexp.MustCompile(`uses:\s+([^@\s#]+)@([a-f0-9]{40})\s*`)
	rePinnedActionSemver = regexp.MustCompile(`uses:\s+([^@\s#]+)@(v\d+\.\d+\.\d+)\s*`)
)

// ciFile describes a CI configuration file location pattern.
type ciFile struct {
	// RelPath is a relative path from workspace root to the CI config file.
	// Glob-style matching: if it contains "*", use filepath.Glob.
	RelPath string
	// Type identifies the CI system.
	Type string
}

// ciFiles lists all CI config files to scan.
var ciFiles = []ciFile{
	{RelPath: ".github/workflows/*.yml", Type: "github-actions"},
	{RelPath: ".github/workflows/*.yaml", Type: "github-actions"},
	{RelPath: ".gitlab-ci.yml", Type: "gitlab-ci"},
	{RelPath: ".gitlab-ci.yaml", Type: "gitlab-ci"},
	{RelPath: "Jenkinsfile", Type: "jenkins"},
	{RelPath: ".circleci/config.yml", Type: "circleci"},
	{RelPath: ".circleci/config.yaml", Type: "circleci"},
	{RelPath: "bitbucket-pipelines.yml", Type: "bitbucket"},
	{RelPath: "bitbucket-pipelines.yaml", Type: "bitbucket"},
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/policy-gate", version).
		Capability("policy-gate", "Detects missing CI/CD security gates and policy enforcement gaps").
		Tool("scan", "Scan CI/CD configurations for missing security gates and policy enforcement", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	files := discoverCIFiles(workspaceRoot)
	if len(files) == 0 {
		return resp.Build(), nil
	}

	for _, cf := range files {
		if ctx.Err() != nil {
			break
		}
		scanCIFile(resp, cf.path, cf.ciType)
	}

	return resp.Build(), nil
}

// discoveredFile holds a discovered CI config file path and its type.
type discoveredFile struct {
	path   string
	ciType string
}

// discoverCIFiles finds all CI configuration files in the workspace.
func discoverCIFiles(root string) []discoveredFile {
	var result []discoveredFile

	for _, cf := range ciFiles {
		pattern := filepath.Join(root, cf.RelPath)
		if strings.Contains(cf.RelPath, "*") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			for _, m := range matches {
				result = append(result, discoveredFile{path: m, ciType: cf.Type})
			}
		} else {
			if info, err := os.Stat(pattern); err == nil && !info.IsDir() {
				result = append(result, discoveredFile{path: pattern, ciType: cf.Type})
			}
		}
	}

	return result
}

// scanCIFile runs all policy rules against a single CI configuration file.
func scanCIFile(resp *sdk.ResponseBuilder, filePath, ciType string) {
	lines, err := readLines(filePath)
	if err != nil {
		return
	}

	content := strings.Join(lines, "\n")

	checkBranchProtection(resp, filePath, content, ciType)
	checkSecurityScanning(resp, filePath, content, ciType)
	checkDeploymentApproval(resp, filePath, lines, content, ciType)
	checkDependencyAudit(resp, filePath, content, ciType)
	checkInsecurePractices(resp, filePath, lines, ciType)
}

// readLines reads all lines from a file.
func readLines(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// checkBranchProtection checks for POLICY-001: missing branch protection configuration.
func checkBranchProtection(resp *sdk.ResponseBuilder, filePath, content, ciType string) {
	if reRequiredReviewers.MatchString(content) {
		return
	}

	resp.Finding(
		"POLICY-001",
		sdk.SeverityHigh,
		sdk.ConfidenceHigh,
		fmt.Sprintf("No branch protection configuration detected in %s pipeline", ciType),
	).
		At(filePath, 1, 1).
		WithMetadata("ci_system", ciType).
		WithMetadata("control", "branch_protection").
		Done()
}

// checkSecurityScanning checks for POLICY-002: missing security scanning step.
func checkSecurityScanning(resp *sdk.ResponseBuilder, filePath, content, ciType string) {
	hasSAST := reSASTStep.MatchString(content)
	hasDAST := reDASTStep.MatchString(content)
	hasSecrets := reSecretsStep.MatchString(content)

	if hasSAST || hasDAST || hasSecrets {
		return
	}

	resp.Finding(
		"POLICY-002",
		sdk.SeverityMedium,
		sdk.ConfidenceHigh,
		fmt.Sprintf("CI pipeline has no security scanning step (no SAST, DAST, or secrets scanning) in %s config", ciType),
	).
		At(filePath, 1, 1).
		WithMetadata("ci_system", ciType).
		WithMetadata("control", "security_scanning").
		Done()
}

// checkDeploymentApproval checks for POLICY-003: deployment without approval gate.
func checkDeploymentApproval(resp *sdk.ResponseBuilder, filePath string, lines []string, content, ciType string) {
	hasDeployProd := reDeployProd.MatchString(content)
	if !hasDeployProd {
		return
	}

	hasApproval := reApprovalGate.MatchString(content)
	hasManual := reManualTrigger.MatchString(content)

	if hasApproval || hasManual {
		return
	}

	// Find the line where deploy-to-prod occurs for precise location.
	lineNum := 1
	for i, line := range lines {
		if reDeployProd.MatchString(line) {
			lineNum = i + 1
			break
		}
	}

	resp.Finding(
		"POLICY-003",
		sdk.SeverityHigh,
		sdk.ConfidenceMedium,
		fmt.Sprintf("Deployment to production without approval gate in %s pipeline", ciType),
	).
		At(filePath, lineNum, lineNum).
		WithMetadata("ci_system", ciType).
		WithMetadata("control", "deployment_approval").
		Done()
}

// checkDependencyAudit checks for POLICY-004: missing dependency audit step.
func checkDependencyAudit(resp *sdk.ResponseBuilder, filePath, content, ciType string) {
	if reDepAudit.MatchString(content) {
		return
	}

	resp.Finding(
		"POLICY-004",
		sdk.SeverityMedium,
		sdk.ConfidenceMedium,
		fmt.Sprintf("No dependency audit step found in %s pipeline", ciType),
	).
		At(filePath, 1, 1).
		WithMetadata("ci_system", ciType).
		WithMetadata("control", "dependency_audit").
		Done()
}

// checkInsecurePractices checks for POLICY-005: insecure CI pipeline practices.
func checkInsecurePractices(resp *sdk.ResponseBuilder, filePath string, lines []string, ciType string) {
	for i, line := range lines {
		lineNum := i + 1

		// Check for hardcoded secrets.
		if reHardcodedSecret.MatchString(line) {
			resp.Finding(
				"POLICY-005",
				sdk.SeverityMedium,
				sdk.ConfidenceHigh,
				"Hardcoded secret detected in CI pipeline configuration",
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("ci_system", ciType).
				WithMetadata("practice", "hardcoded_secret").
				Done()
		}

		// Check for running as root.
		if reRunAsRoot.MatchString(line) {
			resp.Finding(
				"POLICY-005",
				sdk.SeverityMedium,
				sdk.ConfidenceHigh,
				"CI pipeline runs with elevated privileges (root or --privileged)",
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("ci_system", ciType).
				WithMetadata("practice", "run_as_root").
				Done()
		}

		// Check for unpinned third-party actions (GitHub Actions only).
		if ciType == "github-actions" && reUnpinnedAction.MatchString(line) {
			// Skip if it is pinned to a SHA or full semver.
			if reUnpinnedActionSHA.MatchString(line) || rePinnedActionSemver.MatchString(line) {
				continue
			}
			// Skip first-party actions (actions/).
			matches := reUnpinnedAction.FindStringSubmatch(line)
			if len(matches) >= 2 && strings.HasPrefix(matches[1], "actions/") {
				continue
			}
			resp.Finding(
				"POLICY-005",
				sdk.SeverityMedium,
				sdk.ConfidenceHigh,
				fmt.Sprintf("Third-party GitHub Action used without pinned SHA: %s", strings.TrimSpace(line)),
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("ci_system", ciType).
				WithMetadata("practice", "unpinned_action").
				Done()
		}
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-policy-gate: %v\n", err)
		return 1
	}
	return 0
}
