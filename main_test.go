package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackPolicyGovernance)
}

func TestScanFindsBranchProtectionMissing(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "POLICY-001")
	if len(found) == 0 {
		t.Fatal("expected at least one POLICY-001 (branch protection) finding")
	}
}

func TestScanFindsNoSecurityScanning(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "POLICY-002")
	if len(found) == 0 {
		t.Fatal("expected at least one POLICY-002 (no security scanning) finding")
	}
}

func TestScanFindsDeployWithoutApproval(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "POLICY-003")
	if len(found) == 0 {
		t.Fatal("expected at least one POLICY-003 (deploy without approval) finding")
	}
}

func TestScanFindsMissingDepAudit(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "POLICY-004")
	if len(found) == 0 {
		t.Fatal("expected at least one POLICY-004 (missing dep audit) finding")
	}
}

func TestScanFindsInsecurePractices(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "POLICY-005")
	if len(found) == 0 {
		t.Fatal("expected at least one POLICY-005 (insecure CI practices) finding")
	}

	// Verify we detect both hardcoded secrets and unpinned actions.
	var hasHardcoded, hasUnpinned bool
	for _, f := range found {
		if v, ok := f.GetMetadata()["practice"]; ok {
			switch v {
			case "hardcoded_secret":
				hasHardcoded = true
			case "unpinned_action":
				hasUnpinned = true
			}
		}
	}
	if !hasHardcoded {
		t.Error("expected POLICY-005 finding with practice=hardcoded_secret")
	}
	if !hasUnpinned {
		t.Error("expected POLICY-005 finding with practice=unpinned_action")
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestDiscoverCIFiles(t *testing.T) {
	files := discoverCIFiles(testdataDir(t))
	if len(files) == 0 {
		t.Fatal("expected to discover at least one CI config file in testdata")
	}

	var hasGHA bool
	for _, f := range files {
		if f.ciType == "github-actions" {
			hasGHA = true
		}
	}
	if !hasGHA {
		t.Error("expected to discover GitHub Actions workflow files")
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
