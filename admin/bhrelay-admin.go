package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const appName = "BH Socket Relay Admin"

type config struct {
	ListenAddr string
	CLIPath    string
	CLIHost    string
	CLIPort    string
	DataDir    string
	User       string
	Password   string
}

type server struct {
	cfg     config
	client  *http.Client
	secrets *secretStore
	audit   *auditLog
	tpl     *template.Template
}

type apiError struct {
	Error string `json:"error"`
}

type stats struct {
	Uptime      string `json:"uptime"`
	Period      string `json:"period"`
	GSListen    uint64 `json:"gs_listen"`
	GSBadAuth   uint64 `json:"gs_bad_auth"`
	GSConnect   uint64 `json:"gs_connect"`
	GSRefused   uint64 `json:"gs_refused"`
	Listening   uint64 `json:"listening"`
	Connected   uint64 `json:"connected"`
	BadAuthWait uint64 `json:"bad_auth_wait"`
	Waiting     uint64 `json:"waiting"`
	Raw         string `json:"raw"`
}

type peer struct {
	ID        uint64 `json:"id"`
	Address   string `json:"address"`
	GSID      string `json:"gs_id"`
	Flags     string `json:"flags"`
	State     string `json:"state"`
	Age       string `json:"age"`
	Server    string `json:"server"`
	Client    string `json:"client,omitempty"`
	Idle      string `json:"idle,omitempty"`
	Traffic   string `json:"traffic,omitempty"`
	BPS       string `json:"bps,omitempty"`
	Raw       string `json:"raw"`
	CanKill   bool   `json:"can_kill"`
	SecretRef string `json:"secret_ref,omitempty"`
}

type secretRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Owner       string    `json:"owner"`
	Fingerprint string    `json:"fingerprint"`
	Status      string    `json:"status"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type createSecretRequest struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
	Notes string `json:"notes"`
}

type createSecretResponse struct {
	Record secretRecord `json:"record"`
	Secret string       `json:"secret"`
}

type updateSecretRequest struct {
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

type secretStore struct {
	mu      sync.RWMutex
	path    string
	records []secretRecord
}

type auditEvent struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Details string    `json:"details,omitempty"`
	IP      string    `json:"ip,omitempty"`
}

type auditLog struct {
	mu   sync.Mutex
	path string
}

func main() {
	cfg := loadConfig()
	if cfg.User == "" || cfg.Password == "" {
		log.Fatal("BH_ADMIN_USER and BH_ADMIN_PASSWORD must be set")
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	secrets, err := openSecretStore(filepath.Join(cfg.DataDir, "secrets.json"))
	if err != nil {
		log.Fatalf("open secret store: %v", err)
	}

	s := &server{
		cfg:     cfg,
		client:  &http.Client{Timeout: 10 * time.Second},
		secrets: secrets,
		audit:   &auditLog{path: filepath.Join(cfg.DataDir, "audit.jsonl")},
		tpl:     template.Must(template.New("index").Parse(indexHTML)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/api/health", s.requireAuth(s.handleHealth))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/api/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/api/peers/kill", s.requireAuth(s.handleKillPeer))
	mux.HandleFunc("/api/secrets", s.requireAuth(s.handleSecrets))
	mux.HandleFunc("/api/secrets/", s.requireAuth(s.handleSecret))
	mux.HandleFunc("/api/audit", s.requireAuth(s.handleAudit))

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("%s listening on %s", appName, cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() config {
	return config{
		ListenAddr: env("BH_ADMIN_LISTEN", "127.0.0.1:8730"),
		CLIPath:    env("BH_ADMIN_CLI", "/usr/bin/gsrn_cli"),
		CLIHost:    env("BH_ADMIN_CLI_HOST", "127.0.0.1"),
		CLIPort:    env("BH_ADMIN_CLI_PORT", "48001"),
		DataDir:    env("BH_ADMIN_DATA_DIR", "/var/lib/bhsocket-admin"),
		User:       os.Getenv("BH_ADMIN_USER"),
		Password:   os.Getenv("BH_ADMIN_PASSWORD"),
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.User)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="BH Socket Relay Admin"`)
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *server) actor(r *http.Request) string {
	user, _, _ := r.BasicAuth()
	return user
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_ = s.tpl.Execute(w, map[string]string{"Title": appName})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	out, err := s.runCLI(r.Context(), "stats")
	status := "ok"
	if err != nil {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"cli_error":  errString(err),
		"cli_output": strings.TrimSpace(out),
		"listen":     s.cfg.ListenAddr,
	})
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	out, err := s.runCLI(r.Context(), "stats")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiError{Error: err.Error()})
		return
	}
	parsed := parseStats(out)
	writeJSON(w, http.StatusOK, parsed)
}

func (s *server) handlePeers(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	cmd := "list all"
	switch filter {
	case "listening":
		cmd = "list server"
	case "connected":
		cmd = "list client"
	case "bad":
		cmd = "list bad"
	}
	out, err := s.runCLI(r.Context(), cmd)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiError{Error: err.Error()})
		return
	}
	peers := parsePeers(out, s.secrets.list())
	writeJSON(w, http.StatusOK, map[string]any{"peers": peers, "raw": out})
}

func (s *server) handleKillPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
		return
	}
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	req.Address = strings.TrimSpace(req.Address)
	if !regexp.MustCompile(`^[0-9a-fA-F]{32}$`).MatchString(req.Address) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "address must be 32 hex characters"})
		return
	}
	out, err := s.runCLI(r.Context(), "kill "+req.Address)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiError{Error: err.Error()})
		return
	}
	s.audit.write(auditEvent{Time: time.Now().UTC(), Actor: s.actor(r), Action: "kill_peer", Target: req.Address, Details: strings.TrimSpace(out), IP: clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]string{"result": strings.TrimSpace(out)})
}

func (s *server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"secrets": s.secrets.list()})
	case http.MethodPost:
		var req createSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
			return
		}
		secret, rec, err := s.secrets.create(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		s.audit.write(auditEvent{Time: time.Now().UTC(), Actor: s.actor(r), Action: "create_secret", Target: rec.ID, Details: rec.Name, IP: clientIP(r)})
		writeJSON(w, http.StatusCreated, createSecretResponse{Record: rec, Secret: secret})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
	}
}

func (s *server) handleSecret(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if id == "" {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req updateSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
			return
		}
		rec, err := s.secrets.update(id, req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		s.audit.write(auditEvent{Time: time.Now().UTC(), Actor: s.actor(r), Action: "update_secret", Target: rec.ID, Details: rec.Status, IP: clientIP(r)})
		writeJSON(w, http.StatusOK, rec)
	case http.MethodDelete:
		if err := s.secrets.delete(id); err != nil {
			writeJSON(w, http.StatusNotFound, apiError{Error: err.Error()})
			return
		}
		s.audit.write(auditEvent{Time: time.Now().UTC(), Actor: s.actor(r), Action: "delete_secret", Target: id, IP: clientIP(r)})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
	}
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events, err := s.audit.readLast(200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *server) runCLI(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	args := []string{"-d", s.cfg.CLIHost, "-p", s.cfg.CLIPort}
	cmd := exec.CommandContext(ctx, s.cfg.CLIPath, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %s: %w", s.cfg.CLIPath, err)
	}
	_, _ = io.WriteString(stdin, command+"\nquit\n")
	_ = stdin.Close()

	outBytes, _ := io.ReadAll(outPipe)
	errBytes, _ := io.ReadAll(errPipe)
	err = cmd.Wait()
	out := strings.TrimSpace(string(outBytes))
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, fmt.Errorf("gsrn_cli failed: %w: %s", err, strings.TrimSpace(string(errBytes)))
	}
	if strings.TrimSpace(string(errBytes)) != "" {
		return out, fmt.Errorf("gsrn_cli stderr: %s", strings.TrimSpace(string(errBytes)))
	}
	return out, nil
}

func parseStats(raw string) stats {
	s := stats{Raw: raw}
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "Uptime":
			s.Uptime = val
		case "Period":
			s.Period = val
		case "GS-Listen":
			s.GSListen = parseUint(val)
		case "GS-Bad Auth":
			s.GSBadAuth = parseUint(val)
		case "GS-Connect":
			s.GSConnect = parseUint(val)
		case "GS-Refused":
			s.GSRefused = parseUint(val)
		case "Listening":
			s.Listening = parseUint(val)
		case "Connected":
			s.Connected = parseUint(val)
		case "BadAuthWait":
			s.BadAuthWait = parseUint(val)
		case "Waiting":
			s.Waiting = parseUint(val)
		}
	}
	return s
}

func parseUint(v string) uint64 {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[0], 10, 64)
	return n
}

var peerLine = regexp.MustCompile(`^\[\s*(\d+)\]\s+([0-9a-fA-F]{32})\s+0x([0-9a-fA-F]+)\s+([^\s]+)\s+([A-Z_]+)\s+([^\s]+)\s+([0-9.]+:\d+)(?:\s+-\s+([0-9.]+:\d+)\s+\(\s*([^)]+)\)\s+([^\s]+)\s+\[([^\]]+)\])?`)

func parsePeers(raw string, secrets []secretRecord) []peer {
	var peers []peer
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		m := peerLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, _ := strconv.ParseUint(m[1], 10, 64)
		p := peer{
			ID:      id,
			Address: strings.ToLower(m[2]),
			GSID:    "0x" + strings.ToLower(m[3]),
			Flags:   m[4],
			State:   m[5],
			Age:     m[6],
			Server:  m[7],
			Raw:     line,
			CanKill: true,
		}
		if len(m) > 8 {
			p.Client = strings.TrimSpace(m[8])
			p.Idle = strings.TrimSpace(m[9])
			p.Traffic = strings.TrimSpace(m[10])
			p.BPS = strings.TrimSpace(m[11])
		}
		for _, rec := range secrets {
			if strings.EqualFold(rec.Fingerprint, fingerprintShort(p.Address)) {
				p.SecretRef = rec.Name
				break
			}
		}
		peers = append(peers, p)
	}
	return peers
}

func openSecretStore(path string) (*secretStore, error) {
	st := &secretStore{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		st.records = []secretRecord{}
		return st, st.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		st.records = []secretRecord{}
		return st, nil
	}
	if err := json.Unmarshal(b, &st.records); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *secretStore) list() []secretRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]secretRecord, len(s.records))
	copy(out, s.records)
	return out
}

func (s *secretStore) create(req createSecretRequest) (string, secretRecord, error) {
	name := strings.TrimSpace(req.Name)
	owner := strings.TrimSpace(req.Owner)
	if name == "" || owner == "" {
		return "", secretRecord{}, errors.New("name and owner are required")
	}
	secret, err := randomSecret()
	if err != nil {
		return "", secretRecord{}, err
	}
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte(secret))
	rec := secretRecord{
		ID:          newID(),
		Name:        name,
		Owner:       owner,
		Fingerprint: hex.EncodeToString(sum[:])[:24],
		Status:      "active",
		Notes:       strings.TrimSpace(req.Notes),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	if err := s.saveLocked(); err != nil {
		return "", secretRecord{}, err
	}
	return secret, rec, nil
}

func (s *secretStore) update(id string, req updateSecretRequest) (secretRecord, error) {
	status := strings.TrimSpace(req.Status)
	if status != "active" && status != "revoked" && status != "rotating" {
		return secretRecord{}, errors.New("status must be active, revoked, or rotating")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.records {
		if s.records[i].ID == id {
			s.records[i].Status = status
			s.records[i].Notes = strings.TrimSpace(req.Notes)
			s.records[i].UpdatedAt = time.Now().UTC()
			if err := s.saveLocked(); err != nil {
				return secretRecord{}, err
			}
			return s.records[i], nil
		}
	}
	return secretRecord{}, errors.New("secret record not found")
}

func (s *secretStore) delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.records {
		if s.records[i].ID == id {
			s.records = append(s.records[:i], s.records[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("secret record not found")
}

func (s *secretStore) saveLocked() error {
	tmp := s.path + ".tmp"
	b, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "bh_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newID() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func fingerprintShort(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:24]
}

func (a *auditLog) write(ev auditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(a.path), 0700)
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("audit open: %v", err)
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(ev)
}

func (a *auditLog) readLast(limit int) ([]auditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return []auditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []auditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev auditEvent
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			events = append(events, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:dark;--bg:#111315;--panel:#1b1f23;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;border-bottom:1px solid var(--line);background:#161b22;position:sticky;top:0;z-index:2}
h1{font-size:17px;margin:0;font-weight:650}.status{display:flex;align-items:center;gap:8px;color:var(--muted)}.dot{width:9px;height:9px;border-radius:50%;background:var(--warn)}.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}
main{padding:20px;display:grid;grid-template-columns:280px 1fr;gap:18px}.side{display:flex;flex-direction:column;gap:12px}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.metric b{display:block;font-size:24px;margin-top:4px}.metric span,.muted{color:var(--muted)}
.toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:12px}.tabs{display:flex;gap:6px}.tabs button,.btn,select,input,textarea{border:1px solid var(--line);background:#21262d;color:var(--text);border-radius:6px;padding:8px 10px;font:inherit}.tabs button.active,.btn.primary{background:var(--accent);border-color:var(--accent);color:#07111f}.btn.bad{background:#3b1518;border-color:#7d272d;color:#ffb3b8}.btn:disabled{opacity:.5}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:9px 8px;vertical-align:middle}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}td code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9}.state{font-weight:650}.state.LISTENING{color:var(--ok)}.state.CONNECTED{color:var(--accent)}.state.BAD_AUTH{color:var(--bad)}
form{display:grid;gap:10px}label{display:grid;gap:5px;color:var(--muted)}input,textarea{width:100%}textarea{min-height:70px;resize:vertical}.secret-once{background:#0d2818;border:1px solid #2ea043;border-radius:8px;padding:10px;margin:10px 0;overflow:auto}.hidden{display:none}
@media(max-width:900px){main{grid-template-columns:1fr}.grid{grid-template-columns:1fr}header{padding:0 14px}main{padding:14px}}
</style>
</head>
<body>
<header><h1>BH Socket Relay Admin</h1><div class="status"><span id="healthDot" class="dot"></span><span id="healthText">Checking</span></div></header>
<main>
<aside class="side">
<div class="metric"><span>Listening</span><b id="mListening">0</b></div>
<div class="metric"><span>Connected</span><b id="mConnected">0</b></div>
<div class="metric"><span>Bad Auth</span><b id="mBad">0</b></div>
<div class="metric"><span>Uptime</span><b id="mUptime" style="font-size:15px">-</b></div>
</aside>
<section class="panel">
<div class="toolbar"><div class="tabs"><button class="active" data-view="peers">Peers</button><button data-view="secrets">Secrets</button><button data-view="audit">Audit</button></div><button class="btn" id="refresh">Refresh</button></div>
<div id="viewPeers">
<div class="toolbar"><select id="peerFilter"><option value="">All</option><option value="listening">Listening</option><option value="connected">Connected</option><option value="bad">Bad Auth</option></select></div>
<div style="overflow:auto"><table><thead><tr><th>ID</th><th>Address</th><th>State</th><th>Server</th><th>Client</th><th>Traffic</th><th></th></tr></thead><tbody id="peerRows"></tbody></table></div>
</div>
<div id="viewSecrets" class="hidden">
<div class="grid">
<div>
<h2 style="font-size:15px;margin:0 0 10px">Issue Secret</h2>
<form id="secretForm"><label>Name<input name="name" required></label><label>Owner<input name="owner" required></label><label>Notes<textarea name="notes"></textarea></label><button class="btn primary">Generate</button></form>
<div id="secretOnce" class="secret-once hidden"></div>
</div>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Owner</th><th>Fingerprint</th><th>Status</th><th></th></tr></thead><tbody id="secretRows"></tbody></table></div>
</div>
</div>
<div id="viewAudit" class="hidden"><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead><tbody id="auditRows"></tbody></table></div></div>
</section>
</main>
<script>
const $=s=>document.querySelector(s);const $$=s=>Array.from(document.querySelectorAll(s));let view='peers';
async function api(url,opts={}){const r=await fetch(url,{headers:{'content-type':'application/json'},...opts});const j=await r.json().catch(()=>({error:'bad json'}));if(!r.ok)throw new Error(j.error||r.statusText);return j}
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function loadHealth(){try{const h=await api('/api/health');$('#healthDot').className='dot '+(h.status==='ok'?'ok':'bad');$('#healthText').textContent=h.status}catch(e){$('#healthDot').className='dot bad';$('#healthText').textContent='offline'}}
async function loadStats(){try{const s=await api('/api/stats');$('#mListening').textContent=s.listening;$('#mConnected').textContent=s.connected;$('#mBad').textContent=s.gs_bad_auth;$('#mUptime').textContent=s.uptime||'-'}catch(e){}}
async function loadPeers(){const f=$('#peerFilter').value;const j=await api('/api/peers'+(f?'?filter='+encodeURIComponent(f):''));$('#peerRows').innerHTML=j.peers.map(p=>'<tr><td>'+p.id+'</td><td><code>'+esc(p.address)+'</code><div class="muted">'+esc(p.gs_id)+' '+esc(p.secret_ref||'')+'</div></td><td class="state '+esc(p.state)+'">'+esc(p.state)+'<div class="muted">'+esc(p.age)+'</div></td><td>'+esc(p.server)+'</td><td>'+esc(p.client||'-')+'</td><td>'+esc(p.traffic||'-')+'<div class="muted">'+esc(p.bps||'')+'</div></td><td><button class="btn bad" onclick="killPeer(\''+esc(p.address)+'\')">Kill</button></td></tr>').join('')||'<tr><td colspan="7" class="muted">No peers</td></tr>'}
async function killPeer(address){if(!confirm('Disconnect '+address+'?'))return;await api('/api/peers/kill',{method:'POST',body:JSON.stringify({address})});await refresh()}
async function loadSecrets(){const j=await api('/api/secrets');$('#secretRows').innerHTML=j.secrets.map(s=>'<tr><td>'+esc(s.name)+'<div class="muted">'+esc(s.notes||'')+'</div></td><td>'+esc(s.owner)+'</td><td><code>'+esc(s.fingerprint)+'</code></td><td>'+esc(s.status)+'</td><td><select onchange="setSecret(\''+esc(s.id)+'\',this.value)"><option '+(s.status==='active'?'selected':'')+'>active</option><option '+(s.status==='rotating'?'selected':'')+'>rotating</option><option '+(s.status==='revoked'?'selected':'')+'>revoked</option></select></td></tr>').join('')||'<tr><td colspan="5" class="muted">No secret records</td></tr>'}
async function setSecret(id,status){await api('/api/secrets/'+id,{method:'PATCH',body:JSON.stringify({status})});await loadSecrets()}
async function loadAudit(){const j=await api('/api/audit');$('#auditRows').innerHTML=j.events.map(e=>'<tr><td>'+esc(e.time)+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td><td><code>'+esc(e.target||'')+'</code></td><td>'+esc(e.details||'')+'</td></tr>').join('')||'<tr><td colspan="5" class="muted">No audit events</td></tr>'}
async function refresh(){await loadHealth();await loadStats();if(view==='peers')await loadPeers();if(view==='secrets')await loadSecrets();if(view==='audit')await loadAudit()}
$$('.tabs button').forEach(b=>b.onclick=()=>{view=b.dataset.view;$$('.tabs button').forEach(x=>x.classList.toggle('active',x===b));$('#viewPeers').classList.toggle('hidden',view!=='peers');$('#viewSecrets').classList.toggle('hidden',view!=='secrets');$('#viewAudit').classList.toggle('hidden',view!=='audit');refresh()});
$('#refresh').onclick=refresh;$('#peerFilter').onchange=loadPeers;
$('#secretForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);const res=await api('/api/secrets',{method:'POST',body:JSON.stringify(Object.fromEntries(fd.entries()))});$('#secretOnce').classList.remove('hidden');$('#secretOnce').innerHTML='<b>Copy now. This secret is shown once:</b><br><code>'+esc(res.secret)+'</code>';e.target.reset();await loadSecrets()};
refresh();setInterval(refresh,10000);
</script>
</body>
</html>`
