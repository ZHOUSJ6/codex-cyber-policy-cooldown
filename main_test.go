package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"codex-cyber-policy-cooldown/cpasdk/pluginapi"
)

func resetTestState(t *testing.T, configYAML string) {
	t.Helper()
	banStore.clearAll()
	configStore.store(defaultPluginConfig())
	raw, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte(configYAML)})
	if err != nil {
		t.Fatalf("marshal lifecycle request: %v", err)
	}
	if err := configure(raw); err != nil {
		t.Fatalf("configure plugin: %v", err)
	}
}

func callUsage(t *testing.T, record pluginapi.UsageRecord) {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal usage record: %v", err)
	}
	response, err := handleUsage(raw)
	if err != nil {
		t.Fatalf("handle usage: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(response, &env); err != nil {
		t.Fatalf("decode usage response: %v", err)
	}
	if !env.OK {
		t.Fatalf("usage response error: %#v", env.Error)
	}
}

func callScheduler(t *testing.T, request pluginapi.SchedulerPickRequest) envelope {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal scheduler request: %v", err)
	}
	response, err := handleSchedulerPick(raw)
	if err != nil {
		t.Fatalf("scheduler pick: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(response, &env); err != nil {
		t.Fatalf("decode scheduler response: %v", err)
	}
	return env
}

func TestCyberPolicyFailureCoolsEntireCredential(t *testing.T) {
	resetTestState(t, "cooldown_seconds: 120\nmatch_errors:\n  - cyber_policy\n")
	before := time.Now()

	callUsage(t, pluginapi.UsageRecord{
		Provider: "codex",
		AuthID:   "auth-a",
		Failed:   true,
		Failure: pluginapi.UsageFailure{
			StatusCode: 400,
			Body:       `{"error":{"type":"invalid_request","code":"CYBER_POLICY","message":"blocked"}}`,
		},
	})

	entry, ok := banStore.lookup("auth-a")
	if !ok {
		t.Fatal("auth-a was not put into credential-wide cooldown")
	}
	if entry.Trigger != "error:cyber_policy" {
		t.Fatalf("trigger = %q, want error:cyber_policy", entry.Trigger)
	}
	if entry.ResetAt.Before(before.Add(119*time.Second)) || entry.ResetAt.After(before.Add(121*time.Second)) {
		t.Fatalf("reset_at = %v, want about 120 seconds after %v", entry.ResetAt, before)
	}

	env := callScheduler(t, pluginapi.SchedulerPickRequest{
		Candidates: []pluginapi.SchedulerAuthCandidate{
			{ID: "auth-a", Provider: "codex", Priority: 100},
			{ID: "auth-b", Provider: "codex", Priority: 10},
		},
	})
	if !env.OK {
		t.Fatalf("scheduler returned error: %#v", env.Error)
	}
	var result pluginapi.SchedulerPickResponse
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode scheduler result: %v", err)
	}
	if !result.Handled || result.AuthID != "auth-b" {
		t.Fatalf("scheduler result = %#v, want auth-b", result)
	}
}

func TestUnrelatedFailuresAreIgnored(t *testing.T) {
	resetTestState(t, "")

	for _, record := range []pluginapi.UsageRecord{
		{
			Provider: "codex",
			AuthID:   "auth-429",
			Failed:   true,
			Failure: pluginapi.UsageFailure{
				StatusCode: 429,
				Body:       `{"error":{"code":"rate_limit_exceeded"}}`,
			},
		},
		{
			Provider: "gemini",
			AuthID:   "auth-other-provider",
			Failed:   true,
			Failure: pluginapi.UsageFailure{
				StatusCode: 400,
				Body:       `{"error":{"code":"cyber_policy"}}`,
			},
		},
	} {
		callUsage(t, record)
	}

	if got := len(banStore.snapshot()); got != 0 {
		t.Fatalf("cooldown count = %d, want 0", got)
	}
}

func TestAllCooledCredentialsReturnSchedulerError(t *testing.T) {
	resetTestState(t, "")
	now := time.Now()
	banStore.set("auth-a", banEntry{ResetAt: now.Add(time.Hour), Trigger: "error:cyber_policy", BannedAt: now})
	banStore.set("auth-b", banEntry{ResetAt: now.Add(time.Hour), Trigger: "error:cyber_policy", BannedAt: now})

	env := callScheduler(t, pluginapi.SchedulerPickRequest{
		Candidates: []pluginapi.SchedulerAuthCandidate{
			{ID: "auth-a", Provider: "codex"},
			{ID: "auth-b", Provider: "codex"},
		},
	})
	if env.OK || env.Error == nil {
		t.Fatalf("scheduler envelope = %#v, want explicit cooldown error", env)
	}
	if env.Error.Code != "all_codex_credentials_cooling_down" {
		t.Fatalf("scheduler error code = %q", env.Error.Code)
	}
}

func TestConfigureNormalizesMarkersAndValidatesDuration(t *testing.T) {
	resetTestState(t, "cooldown_seconds: 90\nmatch_errors: [ CYBER_POLICY, custom_code, cyber_policy ]\n")
	cfg := configStore.load()
	if cfg.CooldownSeconds != 90 {
		t.Fatalf("cooldown_seconds = %d, want 90", cfg.CooldownSeconds)
	}
	if strings.Join(cfg.MatchErrors, ",") != "cyber_policy,custom_code" {
		t.Fatalf("match_errors = %#v", cfg.MatchErrors)
	}

	raw, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte("cooldown_seconds: 0\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := configure(raw); err == nil {
		t.Fatal("configure accepted zero cooldown")
	}
}

func TestExpiredCooldownReturnsToBuiltinScheduler(t *testing.T) {
	resetTestState(t, "")
	banStore.set("auth-a", banEntry{
		ResetAt:  time.Now().Add(-time.Second),
		Trigger:  "error:cyber_policy",
		BannedAt: time.Now().Add(-time.Hour),
	})

	env := callScheduler(t, pluginapi.SchedulerPickRequest{
		Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "auth-a", Provider: "codex"}},
	})
	if !env.OK {
		t.Fatalf("scheduler returned error: %#v", env.Error)
	}
	var result pluginapi.SchedulerPickResponse
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Handled || result.DelegateBuiltin != pluginapi.SchedulerBuiltinRoundRobin {
		t.Fatalf("scheduler result = %#v, want built-in round robin", result)
	}
	if _, ok := banStore.lookup("auth-a"); ok {
		t.Fatal("expired cooldown was not cleared")
	}
}
