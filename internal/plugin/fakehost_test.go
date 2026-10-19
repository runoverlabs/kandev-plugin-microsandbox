package plugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

// fakeSandbox is one kandev entry on a fakeMsbctl host.
type fakeSandbox struct {
	rec      msbctl.Record
	binds    []string // secret names it binds
	nonce    string
	agentEnv map[string]string
	binary   []byte
}

// fakeMsbctl is a stateful stand-in for `msbctl kandev` on one host. It
// enforces what the real one does where the plugin depends on it:
// idempotency by operation and digest, capacity, the exact secret set on
// start, and the agentctl binary's size and digest.
type fakeMsbctl struct {
	mu        sync.Mutex
	name      string
	sandboxes map[string]*fakeSandbox
	full      bool
	provReqs  []msbctl.ProvisionRequest
	leaseHdr  map[string]string
	created   int
}

func newFakeMsbctl(name string) *fakeMsbctl {
	return &fakeMsbctl{name: name, sandboxes: map[string]*fakeSandbox{}}
}

func errReply(code string) sshtest.Reply {
	return sshtest.Reply{Stdout: fmt.Sprintf(`{"error":{"code":%q,"message":"fake"}}`, code), Status: 3}
}

func jsonReply(v any) sshtest.Reply {
	out, _ := json.Marshal(v)
	return sshtest.Reply{Stdout: string(out)}
}

func (f *fakeMsbctl) handle(command string, stdin []byte) sshtest.Reply {
	f.mu.Lock()
	defer f.mu.Unlock()
	args := strings.Fields(command)
	if len(args) < 2 || args[0] != "msbctl" {
		return sshtest.Reply{Status: 126}
	}
	if args[1] != "kandev" {
		return f.generic(args[1:])
	}
	if len(args) < 3 {
		return sshtest.Reply{Status: 126}
	}
	verb, rest := args[2], args[3:]
	switch verb {
	case "health":
		used := 0
		for _, s := range f.sandboxes {
			if s.rec.State != msbctl.StateAbsent {
				used++
			}
		}
		max := 8
		if f.full {
			max = used
		}
		return jsonReply(map[string]any{
			"protocol": 1, "kvm": true, "enabled": true, "platform": "linux-amd64",
			"capacity": map[string]any{"max_sandboxes": max, "sandboxes": used, "max_cpus": 64, "max_memory_mib": 1 << 20},
			"serve":    map[string]any{"ok": true, "mode": "none"},
			"tls":      map[string]any{"installed": false},
			"features": msbctl.RequiredFeatures,
		})
	case "provision":
		return f.provision(rest[0], stdin)
	case "agentctl":
		return f.agentctl(rest[0], stdin)
	case "start":
		return f.start(rest[0], stdin)
	case "lease":
		s, ok := f.sandboxes[rest[0]]
		if !ok {
			return errReply("not_found")
		}
		if _, ok := s.rec.Ports[rest[1]]; !ok {
			return errReply("not_found")
		}
		if s.rec.State != msbctl.StateRunning {
			return errReply("unavailable")
		}
		return jsonReply(map[string]any{"lease": msbctl.Lease{
			BaseURL:    fmt.Sprintf("https://%s.tailnet.ts.net:%d", f.name, s.rec.Ports[rest[1]]+10000),
			ExpiresAt:  time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339),
			Generation: fmt.Sprint(s.rec.Generation), Headers: f.leaseHdr,
		}})
	}
	return sshtest.Reply{Status: 126}
}

// generic answers the generic verbs exactly as `host serve --kandev` admits
// them; any other shape is refused with 126, as the real forced command does.
func (f *fakeMsbctl) generic(args []string) sshtest.Reply {
	byName := func(name string) (string, *fakeSandbox) {
		for env, s := range f.sandboxes {
			if s.rec.Name == name {
				return env, s
			}
		}
		return "", nil
	}
	row := func(s *fakeSandbox) map[string]any {
		return map[string]any{"name": s.rec.Name, "source": "kandev", "state": "running", "kandev": s.rec}
	}
	switch {
	case len(args) == 2 && args[0] == "ls" && args[1] == "--json":
		rows := []map[string]any{}
		for _, s := range f.sandboxes {
			rows = append(rows, row(s))
		}
		return jsonReply(map[string]any{"msbctl": "0.3.0 (git checkout)", "sandboxes": rows})
	case len(args) == 3 && args[0] == "show" && args[2] == "--json":
		if _, s := byName(args[1]); s != nil {
			return jsonReply(row(s))
		}
		return errReply("not_found")
	case len(args) == 3 && args[0] == "stop" && args[2] == "--json":
		_, s := byName(args[1])
		if s == nil {
			return errReply("not_found")
		}
		s.rec.State = msbctl.StateStopped
		return jsonReply(map[string]any{"sandboxes": []any{row(s)}})
	case len(args) == 4 && args[0] == "purge" && args[2] == "-y" && args[3] == "--json":
		if env, s := byName(args[1]); s != nil {
			delete(f.sandboxes, env)
			return jsonReply(map[string]any{"purged": []string{args[1]}, "absent": []string{}})
		}
		return jsonReply(map[string]any{"purged": []string{}, "absent": []string{args[1]}})
	}
	return sshtest.Reply{Status: 126}
}

func (f *fakeMsbctl) provision(env string, stdin []byte) sshtest.Reply {
	var req msbctl.ProvisionRequest
	if err := json.Unmarshal(bytes.TrimSuffix(stdin, []byte("\n")), &req); err != nil {
		return errReply("invalid_config")
	}
	if s, ok := f.sandboxes[env]; ok {
		if s.rec.OperationID == req.OperationID && s.rec.InputDigest == req.InputDigest {
			return jsonReply(map[string]any{"record": s.rec})
		}
		return errReply("conflict")
	}
	if f.full {
		return sshtest.Reply{Stdout: `{"error":{"code":"rate_limited","retry_after_seconds":30}}`, Status: 3}
	}
	f.provReqs = append(f.provReqs, req)
	f.created++
	s := &fakeSandbox{rec: msbctl.Record{
		Env: env, Name: "k-" + env, OperationID: req.OperationID, InputDigest: req.InputDigest,
		State: msbctl.StateRunning, Platform: "linux-amd64", Image: req.Image,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: req.ExpiresAt, MaxExpires: req.ExpiresAt,
		Generation: 1, Ports: map[string]int{"8765": 20001, "41001": 20002, "41002": 20003, "41003": 20004},
	}}
	for _, sec := range req.Secrets {
		s.binds = append(s.binds, sec.Name)
	}
	f.sandboxes[env] = s
	return jsonReply(map[string]any{"record": s.rec})
}

func (f *fakeMsbctl) agentctl(env string, stdin []byte) sshtest.Reply {
	s, ok := f.sandboxes[env]
	if !ok {
		return errReply("not_found")
	}
	reader := bufio.NewReader(bytes.NewReader(stdin))
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return errReply("invalid_config")
	}
	var req msbctl.AgentctlRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return errReply("invalid_config")
	}
	binary, _ := io.ReadAll(reader)
	sum := sha256.Sum256(binary)
	if int64(len(binary)) != req.Size || hex.EncodeToString(sum[:]) != req.SHA256 {
		return errReply("invalid_config")
	}
	s.nonce, s.agentEnv, s.binary = req.Nonce, req.Env, binary
	s.rec.Agentctl.Running, s.rec.Agentctl.SHA256 = true, req.SHA256
	return jsonReply(map[string]any{"record": s.rec})
}

func (f *fakeMsbctl) start(env string, stdin []byte) sshtest.Reply {
	s, ok := f.sandboxes[env]
	if !ok {
		return errReply("not_found")
	}
	if s.rec.State == msbctl.StateRunning {
		return jsonReply(map[string]any{"record": s.rec})
	}
	var req struct {
		Secrets []msbctl.Secret `json:"secrets"`
	}
	_ = json.Unmarshal(bytes.TrimSuffix(stdin, []byte("\n")), &req)
	if len(req.Secrets) != len(s.binds) {
		return errReply("invalid_config")
	}
	s.rec.State, s.rec.Generation = msbctl.StateRunning, s.rec.Generation+1
	s.rec.Agentctl.Running = false
	return jsonReply(map[string]any{"record": s.rec})
}

func (f *fakeMsbctl) sandbox(env string) *fakeSandbox {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sandboxes[env]
}

func (f *fakeMsbctl) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sandboxes)
}

// fakeProviderAPI is Kandev's side of the provider callbacks.
type fakeProviderAPI struct {
	mu          sync.Mutex
	artifact    []byte
	platforms   []string
	checkpoints []*pluginsdk.CheckpointExecutorResourceRequest
	stages      []string
	events      []string // ordered: "checkpoint", "artifact"
	failCheck   bool
}

func (a *fakeProviderAPI) CheckpointExecutorResource(_ context.Context, req *pluginsdk.CheckpointExecutorResourceRequest) (*pluginsdk.CheckpointExecutorResourceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failCheck {
		return nil, fmt.Errorf("checkpoint refused")
	}
	a.checkpoints = append(a.checkpoints, req)
	a.events = append(a.events, "checkpoint")
	return &pluginsdk.CheckpointExecutorResourceResponse{Accepted: true}, nil
}

func (a *fakeProviderAPI) ReportExecutorProgress(_ context.Context, req *pluginsdk.ReportExecutorProgressRequest) (*pluginsdk.ReportExecutorProgressResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stages = append(a.stages, req.GetStage())
	return &pluginsdk.ReportExecutorProgressResponse{Accepted: true}, nil
}

// ReadExecutorRuntimeArtifact chunks like Kandev: 256 KiB, digest on every
// chunk, final on the last.
func (a *fakeProviderAPI) ReadExecutorRuntimeArtifact(_ context.Context, req *pluginsdk.ReadExecutorRuntimeArtifactRequest, send func(*pluginsdk.ExecutorRuntimeArtifactChunk) error) error {
	a.mu.Lock()
	a.platforms = append(a.platforms, req.GetPlatform())
	a.events = append(a.events, "artifact")
	data := a.artifact
	a.mu.Unlock()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for offset, index := 0, uint32(0); offset < len(data); index++ {
		end := min(offset+pluginsdk.MaxExecutorRuntimeArtifactChunkBytes, len(data))
		if err := send(&pluginsdk.ExecutorRuntimeArtifactChunk{
			ArtifactId: req.GetArtifactId(), Version: "sha256:" + digest, TotalSizeBytes: uint64(len(data)),
			Sha256: digest, ChunkIndex: index, Data: data[offset:end], Final: end == len(data),
		}); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// providerFakeHost adds the provider callbacks to fakeHost.
type providerFakeHost struct {
	*fakeHost
	api *fakeProviderAPI
}

func (h providerFakeHost) ExecutorProvider() pluginsdk.ExecutorProviderHostAPI { return h.api }
