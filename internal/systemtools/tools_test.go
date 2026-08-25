package systemtools

import "testing"

func TestResolveStartupOpensTaskManagerStartupPage(t *testing.T) {
	tool, err := Resolve("startup")
	if err != nil {
		t.Fatalf("Resolve(startup): %v", err)
	}
	if tool.Label != "任务管理器启动项" {
		t.Fatalf("Label = %q", tool.Label)
	}
	if tool.Command != "taskmgr.exe" || tool.Arguments != "/0 /startup" {
		t.Fatalf("startup command = %q %q", tool.Command, tool.Arguments)
	}
}

func TestResolveRejectsUnknownTool(t *testing.T) {
	if _, err := Resolve("unknown"); err == nil {
		t.Fatal("Resolve(unknown) succeeded")
	}
}
