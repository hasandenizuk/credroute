// allow-claude-code: see scope.go header.
package scope

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestResolve_GoogleReadOnly_ByTask(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("google", "read-only", "gsc")
	if res.Enforcement != "scope-derived" {
		t.Fatalf("enforcement = %q, want scope-derived", res.Enforcement)
	}
	want := []string{"https://www.googleapis.com/auth/webmasters.readonly"}
	if !reflect.DeepEqual(res.Scopes, want) {
		t.Fatalf("scopes = %v, want %v", res.Scopes, want)
	}
	if res.ExecEnv != "GOOGLE_OAUTH_TOKEN_JSON" {
		t.Fatalf("exec_env = %q, want GOOGLE_OAUTH_TOKEN_JSON", res.ExecEnv)
	}
}

func TestResolve_GoogleReadWrite_ByTask(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("google", "read-write", "ga4")
	want := []string{"https://www.googleapis.com/auth/analytics.edit"}
	if !reflect.DeepEqual(res.Scopes, want) {
		t.Fatalf("scopes = %v, want %v", res.Scopes, want)
	}
}

func TestResolve_GoogleReadOnly_NoTask_FallsBackToUnion(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("google", "read-only", "")
	if res.Enforcement != "scope-derived" {
		t.Fatalf("enforcement = %q, want scope-derived", res.Enforcement)
	}
	if len(res.Scopes) != 3 {
		t.Fatalf("expected the union of gsc/ga4/drive scopes, got %v", res.Scopes)
	}
	got := append([]string(nil), res.Scopes...)
	sort.Strings(got)
	want := []string{
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/webmasters.readonly",
		"https://www.googleapis.com/auth/analytics.readonly",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
}

func TestResolve_GithubReadWrite_FlatScopes(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("github", "read-write", "")
	want := []string{"repo", "workflow"}
	if !reflect.DeepEqual(res.Scopes, want) {
		t.Fatalf("scopes = %v, want %v", res.Scopes, want)
	}
	if res.ExecEnv != "GH_TOKEN" {
		t.Fatalf("exec_env = %q, want GH_TOKEN", res.ExecEnv)
	}
}

func TestResolve_GithubReadOnly_FlatScopes(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("github", "read-only", "")
	want := []string{"repo:status", "read:org"}
	if !reflect.DeepEqual(res.Scopes, want) {
		t.Fatalf("scopes = %v, want %v", res.Scopes, want)
	}
}

func TestResolve_UnknownPlatform_IsGenericPassthrough(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := reg.Resolve("stripe", "read-only", "")
	if res.Enforcement != "advisory" {
		t.Fatalf("enforcement = %q, want advisory", res.Enforcement)
	}
	if len(res.Scopes) != 0 {
		t.Fatalf("expected no scopes for an unknown platform, got %v", res.Scopes)
	}
	if res.Platform != "stripe" || res.AccessLevel != "read-only" {
		t.Fatalf("passthrough must still report the requested platform/access, got %+v", res)
	}
}

func TestNewRegistry_UserProfileOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	content := `platform: google
access_levels:
  read-only:
    scopes:
      custom: ["https://example.com/custom.readonly"]
exec_env: CUSTOM_GOOGLE_TOKEN
`
	if err := os.WriteFile(filepath.Join(dir, "google.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write user profile: %v", err)
	}

	reg, err := NewRegistry(dir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if reg.Source("google") != "user" {
		t.Fatalf("source = %q, want user", reg.Source("google"))
	}
	res := reg.Resolve("google", "read-only", "custom")
	if res.ExecEnv != "CUSTOM_GOOGLE_TOKEN" {
		t.Fatalf("exec_env = %q, want CUSTOM_GOOGLE_TOKEN (user override did not take effect)", res.ExecEnv)
	}
}

func TestNewRegistry_UserDirMissingIsNotAnError(t *testing.T) {
	reg, err := NewRegistry(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, ok := reg.Get("google"); !ok {
		t.Fatal("built-in google profile should still load when the user dir is missing")
	}
}

func TestList_SortedByPlatform(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	list := reg.List()
	if len(list) < 2 {
		t.Fatalf("expected at least google and github built in, got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Platform > list[i].Platform {
			t.Fatalf("List() is not sorted: %s before %s", list[i-1].Platform, list[i].Platform)
		}
	}
}

func TestUserProfilesDir_EnvOverride(t *testing.T) {
	t.Setenv("CREDROUTE_PROFILES_DIR", "/tmp/example-profiles")
	dir, err := UserProfilesDir()
	if err != nil {
		t.Fatalf("UserProfilesDir: %v", err)
	}
	if dir != "/tmp/example-profiles" {
		t.Fatalf("dir = %q, want /tmp/example-profiles", dir)
	}
}
