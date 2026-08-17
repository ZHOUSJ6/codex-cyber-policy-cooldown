// Package main implements the codex-cyber-policy-cooldown CPA plugin.
//
// It cools down an entire Codex credential after an upstream failure body
// matches a configured error marker ("cyber_policy" by default).
//
// Three capabilities are registered:
//   - usage_plugin: observes every completed request. On a matching Codex
//     failure it records a credential-wide cooldown keyed by AuthID.
//   - scheduler: on every credential pick, it drops candidates whose recorded
//     reset time has not yet passed (lazy re-enable, since CPA exposes no
//     timer hook) and delegates the actual selection to the built-in
//     round-robin scheduler.
//   - management_api: exposes a small status page and authenticated API for
//     manually clearing the in-memory cooldown state.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"codex-cyber-policy-cooldown/cpasdk/pluginabi"
	"codex-cyber-policy-cooldown/cpasdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginName    = "codex-cyber-policy-cooldown"
	pluginVersion = "0.1.1"

	// providerCodex is the CPA provider key for OpenAI Codex (ChatGPT backend).
	providerCodex = "codex"

	defaultCooldownSeconds = int64(3600)
	maxCooldownSeconds     = int64(30 * 24 * 60 * 60)

	managementRoutePrefix = "/plugins/" + pluginName
)

// banStore holds, per credential, the time at which it may be used again.
// A credential is absent from the map when it is not currently banned.
// This is in-process memory; CPA plugins are long-lived and loaded once, so
// state persists across requests. It does not survive a CPA restart, which is
// acceptable because a restart also clears CPA's own cooldown state.
var (
	banStore    banState
	configStore = configState{config: defaultPluginConfig()}
)

type configState struct {
	mu     sync.RWMutex
	config pluginConfig
}

type pluginConfig struct {
	MatchErrors     []string `yaml:"match_errors"`
	CooldownSeconds int64    `yaml:"cooldown_seconds"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type banState struct {
	mu   sync.Mutex
	bans map[string]banEntry // keyed by AuthID
}

type banEntry struct {
	// ResetAt is the end of the configured cooldown. The credential is skipped
	// until now >= ResetAt.
	ResetAt time.Time
	// Trigger identifies the configured error marker that triggered cooldown.
	Trigger string
	// BannedAt is when the ban was recorded, for logging only.
	BannedAt time.Time
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		MatchErrors:     []string{"cyber_policy"},
		CooldownSeconds: defaultCooldownSeconds,
	}
}

func (s *configState) load() pluginConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return pluginConfig{
		MatchErrors:     append([]string(nil), s.config.MatchErrors...),
		CooldownSeconds: s.config.CooldownSeconds,
	}
}

func (s *configState) store(config pluginConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pluginConfig{
		MatchErrors:     append([]string(nil), config.MatchErrors...),
		CooldownSeconds: config.CooldownSeconds,
	}
}

// lookup returns the ban entry for the given auth ID and whether one exists.
func (s *banState) lookup(authID string) (banEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bans[authID]
	return e, ok
}

// set records a cooldown for the given auth ID. A repeated failure may extend
// an existing cooldown, but never shortens it.
func (s *banState) set(authID string, e banEntry) banEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		s.bans = make(map[string]banEntry)
	}
	if current, ok := s.bans[authID]; ok && current.ResetAt.After(e.ResetAt) {
		return current
	}
	s.bans[authID] = e
	return e
}

// clearIfExpired removes the ban for authID if its reset time has passed.
// Returns whether the credential is currently banned AFTER this check.
func (s *banState) clearIfExpired(authID string, now time.Time) (stillBanned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bans[authID]
	if !ok {
		return false
	}
	if !now.Before(e.ResetAt) {
		// Reset time has passed: auto re-enable.
		delete(s.bans, authID)
		slog.Info(pluginName+": auto re-enabled credential",
			"auth_id", authID, "trigger", e.Trigger, "reset_at", e.ResetAt.Format(time.RFC3339))
		return false
	}
	return true
}

// clearExpired removes every ban whose reset time has passed.
func (s *banState) clearExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for authID, e := range s.bans {
		if !now.Before(e.ResetAt) {
			delete(s.bans, authID)
			removed++
			slog.Info(pluginName+": auto re-enabled credential",
				"auth_id", authID, "trigger", e.Trigger, "reset_at", e.ResetAt.Format(time.RFC3339))
		}
	}
	return removed
}

// clear removes the ban for authID, if present.
func (s *banState) clear(authID string) (banEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		return banEntry{}, false
	}
	e, ok := s.bans[authID]
	if ok {
		delete(s.bans, authID)
	}
	return e, ok
}

// clearAll removes every active ban and returns how many were removed.
func (s *banState) clearAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.bans)
	s.bans = make(map[string]banEntry)
	return n
}

// snapshot returns a copy of the current bans for diagnostics / management UI.
func (s *banState) snapshot() map[string]banEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]banEntry, len(s.bans))
	for authID, e := range s.bans {
		out[authID] = e
	}
	return out
}

func main() {}

// cliproxy_plugin_init is the native entry point CPA calls when loading the
// plugin. It wires the host reverse-call API and registers our call/free/shutdown
// function pointers.
//
//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

// cliproxyPluginCall is the single dispatch entry CPA invokes for every method.
//
//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

// handleMethod routes a CPA method to its handler.
func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	case pluginabi.MethodSchedulerPick:
		return handleSchedulerPick(request)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return fmt.Errorf("decode plugin lifecycle request: %w", errUnmarshal)
		}
	}

	cfg := defaultPluginConfig()
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return fmt.Errorf("decode plugin config: %w", errUnmarshal)
		}
	}

	patterns := make([]string, 0, len(cfg.MatchErrors))
	seen := make(map[string]struct{}, len(cfg.MatchErrors))
	for _, pattern := range cfg.MatchErrors {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}
	if len(patterns) == 0 {
		return fmt.Errorf("match_errors must contain at least one non-empty marker")
	}
	if cfg.CooldownSeconds < 1 || cfg.CooldownSeconds > maxCooldownSeconds {
		return fmt.Errorf("cooldown_seconds must be between 1 and %d", maxCooldownSeconds)
	}
	cfg.MatchErrors = patterns
	configStore.store(cfg)
	return nil
}

// pluginRegistration declares the plugin's metadata and capabilities.
// Both usage_plugin and scheduler must be true.
func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "ZHOUSJ6",
			GitHubRepository: "https://github.com/ZHOUSJ6/codex-cyber-policy-cooldown",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "match_errors",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Case-insensitive failure-body markers that trigger credential-wide cooldown. Defaults to [cyber_policy].",
				},
				{
					Name:        "cooldown_seconds",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Credential-wide cooldown duration in seconds. Defaults to 3600; maximum 2592000 (30 days).",
				},
			},
		},
		Capabilities: registrationCapability{
			UsagePlugin:   true,
			Scheduler:     true,
			ManagementAPI: true,
		},
	}
}

// handleUsage observes a completed request. A matching Codex failure starts a
// credential-wide cooldown keyed by AuthID; unrelated failures are ignored.
func handleUsage(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return okEnvelope(map[string]any{})
	}
	var record pluginapi.UsageRecord
	if errUnmarshal := json.Unmarshal(raw, &record); errUnmarshal != nil {
		slog.Warn(pluginName+": failed to decode usage record", "error", errUnmarshal)
		return okEnvelope(map[string]any{})
	}

	if !strings.EqualFold(record.Provider, providerCodex) || !record.Failed {
		return okEnvelope(map[string]any{})
	}

	cfg := configStore.load()
	matchedError, matched := matchFailure(record.Failure.Body, cfg.MatchErrors)
	if !matched {
		return okEnvelope(map[string]any{})
	}
	authID := strings.TrimSpace(record.AuthID)
	if authID == "" {
		slog.Warn(pluginName+": matched failure has no AuthID; cannot cool down credential",
			"matched_error", matchedError,
			"status_code", record.Failure.StatusCode)
		return okEnvelope(map[string]any{})
	}

	now := time.Now()
	entry := banStore.set(authID, banEntry{
		ResetAt:  now.Add(time.Duration(cfg.CooldownSeconds) * time.Second),
		Trigger:  "error:" + matchedError,
		BannedAt: now,
	})
	slog.Info(pluginName+": cooling down entire credential after matched failure",
		"auth_id", authID,
		"matched_error", matchedError,
		"status_code", record.Failure.StatusCode,
		"reset_at", entry.ResetAt.Format(time.RFC3339))
	return okEnvelope(map[string]any{})
}

func matchFailure(body string, patterns []string) (string, bool) {
	body = strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return pattern, true
		}
	}
	return "", false
}

// handleSchedulerPick prevents credentials in cooldown from being selected.
func handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	now := time.Now()
	available := make([]pluginapi.SchedulerAuthCandidate, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		// Only Codex credentials are subject to our bans.
		if !strings.EqualFold(candidate.Provider, providerCodex) {
			available = append(available, candidate)
			continue
		}
		// clearIfExpired auto-re-enables credentials whose reset time passed.
		if banStore.clearIfExpired(candidate.ID, now) {
			// Still banned: drop from the candidate list.
			continue
		}
		available = append(available, candidate)
	}

	if len(req.Candidates) == 0 {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}

	// Never delegate an all-cooled-down set to CPA's built-in scheduler: the
	// built-in sees the original candidate list and could select a credential
	// this plugin intentionally excluded.
	if len(available) == 0 {
		return errorEnvelope(
			"all_codex_credentials_cooling_down",
			"all eligible Codex credentials are cooling down after a matched policy failure",
		), nil
	}

	// CPA applies our response as follows (conductor.go):
	//   - if AuthID is set and matches a candidate  -> use exactly that one
	//   - else if DelegateBuiltin is set            -> run the built-in
	//                                                   scheduler over the FULL
	//                                                   candidate set (it cannot
	//                                                   be shrunk by the plugin)
	//   - else (Handled false)                      -> host falls back to its
	//                                                   own built-in scheduler
	//
	// Because DelegateBuiltin would let round-robin pick a banned credential,
	// when anything is banned we pick an available AuthID ourselves. When
	// nothing is banned we delegate to round-robin to preserve normal
	// load-balancing.
	if len(available) == len(req.Candidates) {
		return okEnvelope(pluginapi.SchedulerPickResponse{
			DelegateBuiltin: pluginapi.SchedulerBuiltinRoundRobin,
			Handled:         true,
		})
	}
	// Pick the available candidate with the highest numeric priority value
	// (CPA's convention: higher priority value = higher precedence).
	chosen := available[0]
	for _, c := range available[1:] {
		if c.Priority > chosen.Priority {
			chosen = c
		}
	}
	return okEnvelope(pluginapi.SchedulerPickResponse{
		AuthID:  chosen.ID,
		Handled: true,
	})
}

// managementRegistration exposes a small Management API and resource page for
// inspecting or manually clearing credential cooldowns.
func managementRegistration() pluginapi.ManagementRegistrationResponse {
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{
				Method:      http.MethodGet,
				Path:        managementRoutePrefix + "/cooldowns",
				Description: "List Codex credentials currently cooling down after a matched policy failure.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/clear",
				Description: "Clear one Codex credential cooldown. Body: {\"auth_id\":\"...\"}.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/clear-all",
				Description: "Clear every Codex credential cooldown.",
			},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        "/status",
				Menu:        "Codex Cyber Policy Cooldown",
				Description: "View and manually clear credential-wide cyber policy cooldowns.",
			},
		},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return okEnvelope(dispatchManagement(req))
}

func dispatchManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	switch {
	case method == http.MethodGet && matchesManagementPath(req.Path, "/cooldowns"):
		return jsonManagementResponse(http.StatusOK, currentBanStatus())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/clear"):
		return handleManagementUnban(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/clear-all"):
		return handleManagementUnbanAll()
	case method == http.MethodGet && matchesResourcePath(req.Path, "/status"):
		return htmlManagementResponse(http.StatusOK, managementStatusPage())
	default:
		return jsonManagementResponse(http.StatusNotFound, map[string]any{
			"error":  "not_found",
			"path":   req.Path,
			"method": method,
		})
	}
}

type managementBanStatus struct {
	Plugin    string              `json:"plugin"`
	Version   string              `json:"version"`
	Count     int                 `json:"count"`
	Cooldowns []managementBanInfo `json:"cooldowns"`
}

type managementBanInfo struct {
	AuthID           string `json:"auth_id"`
	Trigger          string `json:"trigger"`
	StartedAt        string `json:"started_at,omitempty"`
	StartedAtUnix    int64  `json:"started_at_unix,omitempty"`
	ResetAt          string `json:"reset_at"`
	ResetAtUnix      int64  `json:"reset_at_unix"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

func currentBanStatus() managementBanStatus {
	now := time.Now()
	banStore.clearExpired(now)
	snapshot := banStore.snapshot()
	bans := make([]managementBanInfo, 0, len(snapshot))
	for authID, entry := range snapshot {
		remaining := int64(0)
		if now.Before(entry.ResetAt) {
			remaining = int64(entry.ResetAt.Sub(now).Seconds())
		}
		info := managementBanInfo{
			AuthID:           authID,
			Trigger:          entry.Trigger,
			ResetAt:          entry.ResetAt.Format(time.RFC3339),
			ResetAtUnix:      entry.ResetAt.Unix(),
			RemainingSeconds: remaining,
		}
		if !entry.BannedAt.IsZero() {
			info.StartedAt = entry.BannedAt.Format(time.RFC3339)
			info.StartedAtUnix = entry.BannedAt.Unix()
		}
		bans = append(bans, info)
	}
	sort.Slice(bans, func(i, j int) bool {
		if bans[i].ResetAtUnix == bans[j].ResetAtUnix {
			return bans[i].AuthID < bans[j].AuthID
		}
		return bans[i].ResetAtUnix < bans[j].ResetAtUnix
	})
	return managementBanStatus{
		Plugin:    pluginName,
		Version:   pluginVersion,
		Count:     len(bans),
		Cooldowns: bans,
	}
}

type managementUnbanRequest struct {
	AuthID string `json:"auth_id"`
	All    bool   `json:"all"`
}

func handleManagementUnban(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementUnbanRequest
	if len(req.Body) > 0 {
		if errUnmarshal := json.Unmarshal(req.Body, &body); errUnmarshal != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{
				"error":   "invalid_json",
				"message": errUnmarshal.Error(),
			})
		}
	}
	if strings.EqualFold(req.Query.Get("all"), "true") || body.All {
		return handleManagementUnbanAll()
	}

	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{
			"error":   "missing_auth_id",
			"message": "provide auth_id in JSON body or query string",
		})
	}

	entry, removed := banStore.clear(authID)
	if removed {
		slog.Info(pluginName+": manually re-enabled credential",
			"auth_id", authID, "trigger", entry.Trigger, "reset_at", entry.ResetAt.Format(time.RFC3339))
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"auth_id": authID,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func handleManagementUnbanAll() pluginapi.ManagementResponse {
	removed := banStore.clearAll()
	if removed > 0 {
		slog.Info(pluginName+": manually re-enabled all credentials", "removed", removed)
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func matchesManagementPath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, managementRoutePrefix+suffix)
}

func matchesResourcePath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, "/v0/resource/plugins/"+pluginName+suffix) ||
		strings.HasSuffix(path, "/plugins/"+pluginName+suffix)
}

func jsonManagementResponse(status int, v any) pluginapi.ManagementResponse {
	raw, errMarshal := json.MarshalIndent(v, "", "  ")
	if errMarshal != nil {
		status = http.StatusInternalServerError
		raw, _ = json.Marshal(map[string]any{
			"error":   "marshal_error",
			"message": errMarshal.Error(),
		})
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: raw,
	}
}

func htmlManagementResponse(status int, body string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: []byte(body),
	}
}

func managementStatusPage() string {
	version := html.EscapeString(pluginVersion)
	return `<!doctype html>
<html lang="zh-Hans">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>codex-cyber-policy-cooldown</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { max-width: 980px; margin: 32px auto; padding: 0 16px; line-height: 1.5; }
    h1 { margin-bottom: 4px; }
    h2 { margin-top: 0; }
    .muted { color: #667085; }
    .card { border: 1px solid #d0d7de; border-radius: 12px; padding: 16px; margin: 16px 0; }
    .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .toolbar h2, .toolbar p { margin-bottom: 0; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button { cursor: pointer; padding: 8px 12px; border: 1px solid #d0d7de; border-radius: 8px; margin: 4px 4px 4px 0; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    button.primary { background: #0969da; border-color: #0969da; color: white; }
    button.danger { background: #cf222e; border-color: #cf222e; color: white; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }
    code { background: rgba(127,127,127,.15); padding: 2px 4px; border-radius: 4px; }
    pre { overflow: auto; background: rgba(127,127,127,.12); padding: 12px; border-radius: 8px; }
    .error { border-color: #cf222e; }
    .error h2, .error p { color: #cf222e; }
  </style>
</head>
<body>
  <h1>codex-cyber-policy-cooldown</h1>
  <p class="muted">版本 ` + version + ` · 查看或手动清除整份 Codex 凭据的策略冷却。页面复用 Management Center 的登录会话，不会单独保存管理密钥。</p>

  <div id="accessPanel" class="card error" hidden>
    <h2>管理中心会话不可用</h2>
    <p id="accessMessage">请返回 Management Center 重新登录后刷新此菜单。</p>
  </div>

  <div class="card">
    <div class="toolbar">
      <div>
        <h2>当前被插件排除的账号</h2>
        <p id="message" class="muted">正在读取 Management Center 会话…</p>
      </div>
      <div class="actions">
        <button id="refreshButton" class="primary" disabled>刷新冷却列表</button>
        <button id="clearAllButton" class="danger" disabled>清除全部冷却</button>
      </div>
    </div>
    <div id="list">尚未加载。</div>
  </div>

  <div class="card">
    <h2>API</h2>
    <pre>GET  /v0/management/plugins/codex-cyber-policy-cooldown/cooldowns
POST /v0/management/plugins/codex-cyber-policy-cooldown/clear      {"auth_id":"..."}
POST /v0/management/plugins/codex-cyber-policy-cooldown/clear-all</pre>
  </div>

  <script>
    (() => {
      "use strict";

      const resourceMarker = "/v0/resource/plugins/";
      const markerIndex = window.location.pathname.indexOf(resourceMarker);
      const pathPrefix = markerIndex >= 0 ? window.location.pathname.slice(0, markerIndex) : "";
      const defaultAPIBase = window.location.origin + pathPrefix;
      const managementPath = "/v0/management/plugins/codex-cyber-policy-cooldown";
      const authStorageKey = "cli-proxy-auth";
      const themeStorageKey = "cli-proxy-theme";
      const encryptedPrefix = "enc::v1::";
      const storageSalt = "cli-proxy-api-webui::secure-storage";

      const elements = {
        accessPanel: document.getElementById("accessPanel"),
        accessMessage: document.getElementById("accessMessage"),
        message: document.getElementById("message"),
        list: document.getElementById("list"),
        refreshButton: document.getElementById("refreshButton"),
        clearAllButton: document.getElementById("clearAllButton")
      };
      const state = {apiBase: "", apiRoot: "", managementKey: "", connected: false};

      function isEmbedded() {
        try {
          return window.self !== window.top;
        } catch (_) {
          return false;
        }
      }

      function xorBytes(data, key) {
        const output = new Uint8Array(data.length);
        for (let index = 0; index < data.length; index += 1) {
          output[index] = data[index] ^ key[index % key.length];
        }
        return output;
      }

      function decodeStoredValue(value) {
        if (!value.startsWith(encryptedPrefix)) return value;
        const binary = atob(value.slice(encryptedPrefix.length));
        const encrypted = Uint8Array.from(binary, function (character) { return character.charCodeAt(0); });
        const key = new TextEncoder().encode(storageSalt + "|" + window.location.host + "|" + navigator.userAgent);
        return new TextDecoder().decode(xorBytes(encrypted, key));
      }

      function extractPanelAuth(value) {
        if (!value || typeof value !== "object") return null;
        const savedState = value.state && typeof value.state === "object" ? value.state : value;
        const apiBase = typeof savedState.apiBase === "string" ? savedState.apiBase.trim() : "";
        const managementKey = typeof savedState.managementKey === "string" ? savedState.managementKey.trim() : "";
        if (!apiBase || !managementKey) return null;
        return {apiBase: apiBase, managementKey: managementKey};
      }

      function readPanelAuth() {
        if (!isEmbedded()) return null;
        try {
          const raw = localStorage.getItem(authStorageKey);
          if (!raw) return null;
          return extractPanelAuth(JSON.parse(decodeStoredValue(raw)));
        } catch (_) {
          return null;
        }
      }

      function readPanelTheme() {
        try {
          const raw = localStorage.getItem(themeStorageKey);
          if (!raw) return "auto";
          const parsed = JSON.parse(raw);
          const savedState = parsed && parsed.state && typeof parsed.state === "object" ? parsed.state : parsed;
          return typeof savedState.theme === "string" ? savedState.theme : "auto";
        } catch (_) {
          return "auto";
        }
      }

      function applyPanelTheme() {
        const theme = readPanelTheme();
        const resolved = theme === "auto"
          ? (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white")
          : theme;
        if (resolved === "dark" || resolved === "white") {
          document.documentElement.setAttribute("data-theme", resolved);
        } else {
          document.documentElement.removeAttribute("data-theme");
        }
      }

      function normalizeAPIBase(value) {
        let base = String(value || "").trim();
        if (!base) return defaultAPIBase;
        base = base.replace(/\/?v0\/management\/?$/i, "").replace(/\/+$/, "");
        if (!/^https?:\/\//i.test(base)) base = "http://" + base;
        try {
          const parsed = new URL(base);
          if (parsed.origin === window.location.origin && (parsed.pathname === "" || parsed.pathname === "/") && pathPrefix) {
            return defaultAPIBase;
          }
        } catch (_) {
          return base;
        }
        return base;
      }

      function setSession(panelAuth) {
        state.apiBase = normalizeAPIBase(panelAuth.apiBase);
        state.managementKey = String(panelAuth.managementKey || "").trim();
        state.apiRoot = state.apiBase + managementPath;
        state.connected = Boolean(state.managementKey);
        elements.refreshButton.disabled = !state.connected;
        elements.clearAllButton.disabled = !state.connected;
      }

      function disconnect(message) {
        state.apiBase = "";
        state.apiRoot = "";
        state.managementKey = "";
        state.connected = false;
        elements.refreshButton.disabled = true;
        elements.clearAllButton.disabled = true;
        elements.accessPanel.hidden = false;
        elements.accessMessage.textContent = message || "请返回 Management Center 重新登录后刷新此菜单。";
        setMessage("管理中心会话不可用。", true);
      }

      function setMessage(text, isError) {
        elements.message.textContent = text || "";
        elements.message.style.color = isError ? "#cf222e" : "";
      }

      function friendlyError(data, status) {
        if (status === 401) return "管理中心会话已失效，请返回 Management Center 重新登录后刷新此菜单。";
        if (status === 403) return "当前管理身份无权访问此接口。";
        return (data && (data.message || data.error)) || ("请求失败（HTTP " + status + "）");
      }

      async function call(path, options) {
        if (!state.connected) throw new Error("管理中心会话不可用。");
        const request = Object.assign({method: "GET"}, options || {});
        request.cache = "no-store";
        request.credentials = "same-origin";
        request.headers = Object.assign({
          "Accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": "Bearer " + state.managementKey
        }, request.headers || {});

        let response;
        try {
          response = await fetch(state.apiRoot + path, request);
        } catch (_) {
          throw new Error("无法连接 CLIProxyAPI，请检查服务地址和网络状态。");
        }
        const text = await response.text();
        let data;
        try { data = JSON.parse(text); } catch (_) { data = {raw: text}; }
        if (!response.ok) {
          const error = new Error(friendlyError(data, response.status));
          error.status = response.status;
          throw error;
        }
        return data;
      }

      function formatRemaining(seconds) {
        seconds = Math.max(0, Number(seconds || 0));
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        if (hours > 0) return hours + "h " + minutes + "m";
        return minutes + "m";
      }

      function appendCell(row, value, asCode) {
        const cell = document.createElement("td");
        if (asCode) {
          const code = document.createElement("code");
          code.textContent = String(value || "");
          cell.appendChild(code);
        } else {
          cell.textContent = String(value || "");
        }
        row.appendChild(cell);
      }

      function render(data) {
        elements.list.replaceChildren();
        if (!data.cooldowns || data.cooldowns.length === 0) {
          const empty = document.createElement("p");
          empty.textContent = "当前没有处于策略冷却中的凭据。";
          elements.list.appendChild(empty);
          return;
        }

        const table = document.createElement("table");
        const head = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["Auth ID", "触发项", "解除时间", "剩余", "操作"].forEach(function (label) {
          const cell = document.createElement("th");
          cell.textContent = label;
          headRow.appendChild(cell);
        });
        head.appendChild(headRow);
        table.appendChild(head);

        const body = document.createElement("tbody");
        data.cooldowns.forEach(function (cooldown) {
          const row = document.createElement("tr");
          appendCell(row, cooldown.auth_id, true);
          appendCell(row, cooldown.trigger, false);
          appendCell(row, cooldown.reset_at, false);
          appendCell(row, formatRemaining(cooldown.remaining_seconds), false);
          const actionCell = document.createElement("td");
          const button = document.createElement("button");
          button.textContent = "清除冷却";
          button.addEventListener("click", function () { clearCooldown(cooldown.auth_id); });
          actionCell.appendChild(button);
          row.appendChild(actionCell);
          body.appendChild(row);
        });
        table.appendChild(body);
        elements.list.appendChild(table);
      }

      function handleRequestError(error) {
        if (error && (error.status === 401 || error.status === 403)) {
          disconnect(error.message);
        } else {
          setMessage(error instanceof Error ? error.message : "请求失败。", true);
        }
      }

      async function refresh() {
        try {
          setMessage("加载中…");
          const data = await call("/cooldowns");
          render(data);
          elements.accessPanel.hidden = true;
          setMessage("已连接 Management Center · 共 " + data.count + " 个账号被排除。");
        } catch (error) {
          handleRequestError(error);
        }
      }

      async function clearCooldown(authID) {
        if (!confirm("确认清除 " + authID + " 的策略冷却？")) return;
        try {
          const data = await call("/clear", {method: "POST", body: JSON.stringify({auth_id: authID})});
          render(data.status);
          setMessage(data.removed ? "已清除冷却：" + authID : "该凭据当前不在冷却列表：" + authID);
        } catch (error) {
          handleRequestError(error);
        }
      }

      async function clearAll() {
        if (!confirm("确认清除全部策略冷却？")) return;
        try {
          const data = await call("/clear-all", {method: "POST", body: "{}"});
          render(data.status);
          setMessage("已清除 " + data.removed + " 个凭据冷却。");
        } catch (error) {
          handleRequestError(error);
        }
      }

      elements.refreshButton.addEventListener("click", refresh);
      elements.clearAllButton.addEventListener("click", clearAll);
      applyPanelTheme();

      if (!isEmbedded()) {
        disconnect("该页面只能从 Management Center 的插件菜单打开。请返回管理中心登录后访问。");
        return;
      }
      const panelAuth = readPanelAuth();
      if (!panelAuth) {
        disconnect("未能读取 Management Center 会话。请重新登录管理中心后刷新此菜单。");
        return;
      }
      setSession(panelAuth);
      refresh();
    })();
  </script>
</body>
</html>`
}

// ---- envelope / response helpers ----

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	UsagePlugin   bool `json:"usage_plugin"`
	Scheduler     bool `json:"scheduler"`
	ManagementAPI bool `json:"management_api"`
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
