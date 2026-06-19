package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
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

	_ "modernc.org/sqlite"
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
	SessionKey string
	PublicURL  string
}

type server struct {
	cfg      config
	client   *http.Client
	secrets  *secretStore
	audit    *auditLog
	installs *installLog
	portal   *portalDB
	tpl      *template.Template
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
	Secret      string    `json:"secret,omitempty"`
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

type installRecord struct {
	Time        time.Time `json:"time"`
	Hostname    string    `json:"hostname"`
	User        string    `json:"user"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Kernel      string    `json:"kernel"`
	InstallPath string    `json:"install_path"`
	RelayPort   string    `json:"relay_port"`
	Secret      string    `json:"secret,omitempty"`
	Token       string    `json:"token,omitempty"`
	PublicIP    string    `json:"public_ip,omitempty"`
	Version     string    `json:"version"`
	IP          string    `json:"ip"`
}

type installLog struct {
	mu   sync.Mutex
	path string
}

type portalDB struct {
	db *sql.DB
}

type portalUser struct {
	ID          string
	Username    string
	DeployToken string
	CreatedAt   time.Time
}

type portalServer struct {
	ID          string
	Time        time.Time
	Hostname    string
	ServerUser  string
	OS          string
	Arch        string
	Kernel      string
	InstallPath string
	RelayPort   string
	Secret      string
	PublicIP    string
	IP          string
	UpdatedAt   time.Time
}

type panelView struct {
	Title         string
	Mode          string
	Error         string
	User          portalUser
	Servers       []portalServer
	DeployCommand string
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
	portal, err := openPortalDB(filepath.Join(cfg.DataDir, "portal.db"))
	if err != nil {
		log.Fatalf("open portal db: %v", err)
	}
	defer portal.Close()

	s := &server{
		cfg:      cfg,
		client:   &http.Client{Timeout: 10 * time.Second},
		secrets:  secrets,
		audit:    &auditLog{path: filepath.Join(cfg.DataDir, "audit.jsonl")},
		installs: &installLog{path: filepath.Join(cfg.DataDir, "installs.jsonl")},
		portal:   portal,
		tpl:      template.Must(template.New("index").Parse(indexHTML)),
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
	mux.HandleFunc("/api/installs", s.requireAuth(s.handleInstalls))
	mux.HandleFunc("/api/install-report", s.handleInstallReport)
	mux.HandleFunc("/panel/", s.handlePanel)
	mux.HandleFunc("/panel/login", s.handlePanelLogin)
	mux.HandleFunc("/panel/register", s.handlePanelRegister)
	mux.HandleFunc("/panel/logout", s.handlePanelLogout)
	mux.HandleFunc("/panel/token/rotate", s.handlePanelRotateToken)

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
		SessionKey: env("BH_SESSION_KEY", os.Getenv("BH_ADMIN_PASSWORD")),
		PublicURL:  env("BH_PUBLIC_URL", "https://bhsocket.io"),
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

func (s *server) handleInstalls(w http.ResponseWriter, r *http.Request) {
	records, err := s.installs.readLast(500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"installs": records})
}

func (s *server) handleInstallReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var rec installRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	rec.Time = time.Now().UTC()
	rec.IP = clientIP(r)
	rec.sanitize()
	if rec.Hostname == "" && rec.OS == "" && rec.InstallPath == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "empty install report"})
		return
	}
	if rec.PublicIP == "" {
		rec.PublicIP = rec.IP
	}
	if rec.Token != "" {
		if err := s.portal.recordServer(r.Context(), rec); err != nil {
			log.Printf("portal record server: %v", err)
		}
	}
	if err := s.installs.write(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func (s *server) handlePanel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/panel/" {
		http.NotFound(w, r)
		return
	}
	u, ok := s.currentUser(r)
	if !ok {
		s.renderPanel(w, panelView{Title: "BlackHat Socket Login", Mode: "login"})
		return
	}
	servers, err := s.portal.serversForUser(r.Context(), u.ID, 1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPanel(w, panelView{
		Title:         "BlackHat Socket Panel",
		Mode:          "dashboard",
		User:          u,
		Servers:       servers,
		DeployCommand: fmt.Sprintf(`BH_TOKEN="%s" bash -c "$(curl -fsSL %s/y)"`, u.DeployToken, strings.TrimRight(s.cfg.PublicURL, "/")),
	})
}

func (s *server) handlePanelLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/panel/", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	u, err := s.portal.authenticate(r.Context(), username, password)
	if err != nil {
		s.renderPanel(w, panelView{Title: "BlackHat Socket Login", Mode: "login", Error: "Invalid username or password"})
		return
	}
	s.setUserCookie(w, u.ID)
	http.Redirect(w, r, "/panel/", http.StatusSeeOther)
}

func (s *server) handlePanelRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/panel/", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(password) < 8 {
		s.renderPanel(w, panelView{Title: "BlackHat Socket Register", Mode: "login", Error: "Username must be 3+ chars and password 8+ chars"})
		return
	}
	u, err := s.portal.createUser(r.Context(), username, password)
	if err != nil {
		s.renderPanel(w, panelView{Title: "BlackHat Socket Register", Mode: "login", Error: err.Error()})
		return
	}
	s.setUserCookie(w, u.ID)
	http.Redirect(w, r, "/panel/", http.StatusSeeOther)
}

func (s *server) handlePanelLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "bh_session", Value: "", Path: "/panel/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: true})
	http.Redirect(w, r, "/panel/", http.StatusSeeOther)
}

func (s *server) handlePanelRotateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/panel/", http.StatusSeeOther)
		return
	}
	u, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/panel/", http.StatusSeeOther)
		return
	}
	if err := s.portal.rotateToken(r.Context(), u.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/panel/", http.StatusSeeOther)
}

func (s *server) renderPanel(w http.ResponseWriter, data panelView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := template.Must(template.New("panel").Parse(panelHTML)).Execute(w, data); err != nil {
		log.Printf("render panel: %v", err)
	}
}

func (s *server) currentUser(r *http.Request) (portalUser, bool) {
	c, err := r.Cookie("bh_session")
	if err != nil || c.Value == "" {
		return portalUser{}, false
	}
	uid, ok := s.verifySession(c.Value)
	if !ok {
		return portalUser{}, false
	}
	u, err := s.portal.userByID(r.Context(), uid)
	if err != nil {
		return portalUser{}, false
	}
	return u, true
}

func (s *server) setUserCookie(w http.ResponseWriter, uid string) {
	exp := time.Now().Add(14 * 24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s:%d", uid, exp)
	mac := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     "bh_session",
		Value:    base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + sig)),
		Path:     "/panel/",
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})
}

func (s *server) verifySession(v string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	payload := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return "", false
	}
	return parts[0], true
}

func (s *server) runCLI(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	args := []string{"-p", s.cfg.CLIPort}
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
	_, _ = io.WriteString(stdin, command+"\n")
	time.Sleep(900 * time.Millisecond)
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
			if strings.EqualFold(rec.Fingerprint, p.Address) || strings.EqualFold(rec.Fingerprint, fingerprintShort(p.Address)) {
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
	fingerprint, err := secretRelayAddress(secret)
	if err != nil {
		return "", secretRecord{}, err
	}
	rec := secretRecord{
		ID:          newID(),
		Name:        name,
		Owner:       owner,
		Secret:      secret,
		Fingerprint: fingerprint,
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

func secretRelayAddress(secret string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	path := env("BH_ADMIN_BH_NETCAT", "/usr/local/bin/bh-netcat")
	cmd := exec.CommandContext(ctx, path, "-s", secret, "-t")
	cmd.Env = append(os.Environ(), "_GSOCKET_SERVER_CHECK_SEC=8")
	out, err := cmd.CombinedOutput()
	raw := string(out)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 61 {
			return "", fmt.Errorf("derive relay address: %w: %s", err, strings.TrimSpace(raw))
		}
	}
	m := regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`).FindString(raw)
	if m == "" {
		return "", fmt.Errorf("derive relay address: no address in output: %s", strings.TrimSpace(raw))
	}
	return strings.ToLower(m), nil
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

func (r *installRecord) sanitize() {
	r.Hostname = cleanField(r.Hostname, 160)
	r.User = cleanField(r.User, 80)
	r.OS = cleanField(r.OS, 80)
	r.Arch = cleanField(r.Arch, 80)
	r.Kernel = cleanField(r.Kernel, 160)
	r.InstallPath = cleanField(r.InstallPath, 260)
	r.RelayPort = cleanField(r.RelayPort, 24)
	r.Secret = cleanField(r.Secret, 160)
	r.Token = cleanField(r.Token, 240)
	r.PublicIP = cleanField(r.PublicIP, 80)
	r.Version = cleanField(r.Version, 80)
}

func cleanField(v string, max int) string {
	v = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, v))
	if len(v) > max {
		return v[:max]
	}
	return v
}

func openPortalDB(path string) (*portalDB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	p := &portalDB{db: db}
	if err := p.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

func (p *portalDB) Close() error {
	return p.db.Close()
}

func (p *portalDB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_salt TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			deploy_token TEXT NOT NULL UNIQUE,
			deploy_token_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_servers (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			time TEXT NOT NULL,
			hostname TEXT NOT NULL,
			server_user TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			kernel TEXT NOT NULL,
			install_path TEXT NOT NULL,
			relay_port TEXT NOT NULL,
			secret TEXT NOT NULL,
			public_ip TEXT NOT NULL,
			ip TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_servers_user_time ON user_servers(user_id, time DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_user_servers_secret ON user_servers(secret)`,
		`CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(deploy_token_hash)`,
	}
	for _, stmt := range stmts {
		if _, err := p.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (p *portalDB) createUser(ctx context.Context, username, password string) (portalUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !regexp.MustCompile(`^[a-z0-9_.-]{3,64}$`).MatchString(username) {
		return portalUser{}, errors.New("username can use a-z, 0-9, dot, dash, underscore")
	}
	salt, err := randomToken(18)
	if err != nil {
		return portalUser{}, err
	}
	token, err := randomToken(32)
	if err != nil {
		return portalUser{}, err
	}
	now := time.Now().UTC()
	u := portalUser{ID: newID(), Username: username, DeployToken: token, CreatedAt: now}
	_, err = p.db.ExecContext(ctx, `INSERT INTO users(id, username, password_salt, password_hash, deploy_token, deploy_token_hash, created_at) VALUES(?,?,?,?,?,?,?)`,
		u.ID, username, salt, passwordHash(password, salt), token, tokenHash(token), now.Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return portalUser{}, errors.New("username already exists")
		}
		return portalUser{}, err
	}
	return u, nil
}

func (p *portalDB) authenticate(ctx context.Context, username, password string) (portalUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var u portalUser
	var salt, stored, created string
	err := p.db.QueryRowContext(ctx, `SELECT id, username, password_salt, password_hash, deploy_token, created_at FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &salt, &stored, &u.DeployToken, &created)
	if err != nil {
		return portalUser{}, errors.New("invalid credentials")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(passwordHash(password, salt))) != 1 {
		return portalUser{}, errors.New("invalid credentials")
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return u, nil
}

func (p *portalDB) userByID(ctx context.Context, id string) (portalUser, error) {
	var u portalUser
	var created string
	err := p.db.QueryRowContext(ctx, `SELECT id, username, deploy_token, created_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.DeployToken, &created)
	if err != nil {
		return portalUser{}, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return u, nil
}

func (p *portalDB) rotateToken(ctx context.Context, userID string) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `UPDATE users SET deploy_token=?, deploy_token_hash=? WHERE id=?`, token, tokenHash(token), userID)
	return err
}

func (p *portalDB) recordServer(ctx context.Context, rec installRecord) error {
	var userID string
	err := p.db.QueryRowContext(ctx, `SELECT id FROM users WHERE deploy_token_hash=?`, tokenHash(rec.Token)).Scan(&userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	key := fingerprintShort(userID + "|" + rec.Secret + "|" + rec.Hostname + "|" + rec.User)
	_, err = p.db.ExecContext(ctx, `INSERT INTO user_servers(id,user_id,time,hostname,server_user,os,arch,kernel,install_path,relay_port,secret,public_ip,ip,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			time=excluded.time, hostname=excluded.hostname, server_user=excluded.server_user, os=excluded.os, arch=excluded.arch,
			kernel=excluded.kernel, install_path=excluded.install_path, relay_port=excluded.relay_port, secret=excluded.secret,
			public_ip=excluded.public_ip, ip=excluded.ip, updated_at=excluded.updated_at`,
		key, userID, rec.Time.Format(time.RFC3339Nano), rec.Hostname, rec.User, rec.OS, rec.Arch, rec.Kernel, rec.InstallPath, rec.RelayPort, rec.Secret, rec.PublicIP, rec.IP, now)
	return err
}

func (p *portalDB) serversForUser(ctx context.Context, userID string, limit int) ([]portalServer, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id,time,hostname,server_user,os,arch,kernel,install_path,relay_port,secret,public_ip,ip,updated_at
		FROM user_servers WHERE user_id=? ORDER BY time DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []portalServer{}
	for rows.Next() {
		var s portalServer
		var t, u string
		if err := rows.Scan(&s.ID, &t, &s.Hostname, &s.ServerUser, &s.OS, &s.Arch, &s.Kernel, &s.InstallPath, &s.RelayPort, &s.Secret, &s.PublicIP, &s.IP, &u); err != nil {
			return nil, err
		}
		s.Time, _ = time.Parse(time.RFC3339Nano, t)
		s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
		out = append(out, s)
	}
	return out, rows.Err()
}

func passwordHash(password, salt string) string {
	sum := []byte(salt + ":" + password)
	for i := 0; i < 120000; i++ {
		h := sha256.Sum256(sum)
		sum = h[:]
	}
	return hex.EncodeToString(sum)
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (l *installLog) write(rec installRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(rec)
}

func (l *installLog) readLast(limit int) ([]installRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []installRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	records := []installRecord{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec installRecord
		if json.Unmarshal(scanner.Bytes(), &rec) == nil {
			records = append(records, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	return records, nil
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
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if ip := strings.TrimSpace(strings.Split(forwarded, ",")[0]); ip != "" {
			return ip
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
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
<div class="toolbar"><div class="tabs"><button class="active" data-view="peers">Peers</button><button data-view="installs">Installs</button><button data-view="secrets">Secrets</button><button data-view="audit">Audit</button></div><button class="btn" id="refresh">Refresh</button></div>
<div id="viewPeers">
<div class="toolbar"><select id="peerFilter"><option value="">All</option><option value="listening">Listening</option><option value="connected">Connected</option><option value="bad">Bad Auth</option></select></div>
<div style="overflow:auto"><table><thead><tr><th>ID</th><th>Address</th><th>State</th><th>Server</th><th>Client</th><th>Traffic</th><th></th></tr></thead><tbody id="peerRows"></tbody></table></div>
</div>
<div id="viewInstalls" class="hidden"><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Host</th><th>System</th><th>Secret</th><th>Path</th><th>Port</th><th>IP</th></tr></thead><tbody id="installRows"></tbody></table></div></div>
<div id="viewSecrets" class="hidden">
<div class="grid">
<div>
<h2 style="font-size:15px;margin:0 0 10px">Issue Secret</h2>
<form id="secretForm"><label>Name<input name="name" required></label><label>Owner<input name="owner" required></label><label>Notes<textarea name="notes"></textarea></label><button class="btn primary">Generate</button></form>
<div id="secretOnce" class="secret-once hidden"></div>
</div>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Owner</th><th>Secret</th><th>Fingerprint</th><th>Status</th><th></th></tr></thead><tbody id="secretRows"></tbody></table></div>
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
async function loadInstalls(){const j=await api('/api/installs');$('#installRows').innerHTML=j.installs.map(i=>'<tr><td>'+esc(i.time)+'</td><td>'+esc(i.hostname||'-')+'<div class="muted">'+esc(i.user||'')+'</div></td><td>'+esc(i.os||'-')+' '+esc(i.arch||'')+'<div class="muted">'+esc(i.kernel||'')+'</div></td><td><code>'+esc(i.secret||'-')+'</code></td><td><code>'+esc(i.install_path||'')+'</code></td><td>'+esc(i.relay_port||'-')+'</td><td>'+esc(i.ip||'-')+'</td></tr>').join('')||'<tr><td colspan="7" class="muted">No installs reported yet</td></tr>'}
async function loadSecrets(){const j=await api('/api/secrets');$('#secretRows').innerHTML=j.secrets.map(s=>'<tr><td>'+esc(s.name)+'<div class="muted">'+esc(s.notes||'')+'</div></td><td>'+esc(s.owner)+'</td><td><code>'+esc(s.secret||'-')+'</code></td><td><code>'+esc(s.fingerprint)+'</code></td><td>'+esc(s.status)+'</td><td><select onchange="setSecret(\''+esc(s.id)+'\',this.value)"><option '+(s.status==='active'?'selected':'')+'>active</option><option '+(s.status==='rotating'?'selected':'')+'>rotating</option><option '+(s.status==='revoked'?'selected':'')+'>revoked</option></select></td></tr>').join('')||'<tr><td colspan="6" class="muted">No secret records</td></tr>'}
async function setSecret(id,status){await api('/api/secrets/'+id,{method:'PATCH',body:JSON.stringify({status})});await loadSecrets()}
async function loadAudit(){const j=await api('/api/audit');$('#auditRows').innerHTML=j.events.map(e=>'<tr><td>'+esc(e.time)+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td><td><code>'+esc(e.target||'')+'</code></td><td>'+esc(e.details||'')+'</td></tr>').join('')||'<tr><td colspan="5" class="muted">No audit events</td></tr>'}
async function refresh(){await loadHealth();await loadStats();if(view==='peers')await loadPeers();if(view==='installs')await loadInstalls();if(view==='secrets')await loadSecrets();if(view==='audit')await loadAudit()}
$$('.tabs button').forEach(b=>b.onclick=()=>{view=b.dataset.view;$$('.tabs button').forEach(x=>x.classList.toggle('active',x===b));$('#viewPeers').classList.toggle('hidden',view!=='peers');$('#viewInstalls').classList.toggle('hidden',view!=='installs');$('#viewSecrets').classList.toggle('hidden',view!=='secrets');$('#viewAudit').classList.toggle('hidden',view!=='audit');refresh()});
$('#refresh').onclick=refresh;$('#peerFilter').onchange=loadPeers;
$('#secretForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);const res=await api('/api/secrets',{method:'POST',body:JSON.stringify(Object.fromEntries(fd.entries()))});$('#secretOnce').classList.remove('hidden');$('#secretOnce').innerHTML='<b>Copy now. This secret is shown once:</b><br><code>'+esc(res.secret)+'</code>';e.target.reset();await loadSecrets()};
refresh();setInterval(refresh,10000);
</script>
</body>
</html>`

const panelHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:dark;--bg:#0b0f14;--panel:#151b23;--line:#2b3847;--text:#eef4f7;--muted:#9aa8b2;--ok:#18c29c;--gold:#d9a441;--bad:#e56b6f}
*{box-sizing:border-box}body{margin:0;background:#0b0f14;color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:28px 0 48px}header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}.brand{font-weight:850;font-size:18px}.nav{display:flex;gap:10px;align-items:center}.nav a,.btn,button,input{border:1px solid var(--line);border-radius:8px;background:#202832;color:var(--text);padding:9px 11px;font:inherit}.nav a{color:var(--muted);text-decoration:none}.btn.primary,button.primary{background:var(--ok);border-color:var(--ok);color:#04110d;font-weight:800}.panel{border:1px solid var(--line);border-radius:8px;background:var(--panel);padding:18px;margin-bottom:16px}.grid{display:grid;grid-template-columns:380px 1fr;gap:16px}.forms{display:grid;gap:16px}form{display:grid;gap:10px}label{display:grid;gap:5px;color:var(--muted)}input{width:100%}.error{border-color:#7d272d;background:#3b1518;color:#ffbec2}.muted{color:var(--muted)}.cmd{position:relative;border:1px solid #20303d;border-radius:8px;background:#071015;margin-top:10px;overflow:hidden}.cmd pre{margin:0;padding:54px 14px 14px;overflow:auto;color:#d9fff3;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace}.copy{position:absolute;top:10px;right:10px;min-width:74px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}td code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#d9fff3;overflow-wrap:anywhere}.secret{max-width:250px}.actions{display:flex;gap:8px;flex-wrap:wrap}h1,h2{margin:0 0 12px}h1{font-size:30px}h2{font-size:18px}.metric{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.metric div{border:1px solid var(--line);border-radius:8px;padding:12px;background:#10161d}.metric b{font-size:24px;display:block}
@media(max-width:900px){.grid{grid-template-columns:1fr}.metric{grid-template-columns:1fr}header{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<main>
<header><div class="brand">BlackHat Socket Panel</div><div class="nav">{{if eq .Mode "dashboard"}}<span class="muted">{{.User.Username}}</span><a href="/panel/logout">Logout</a>{{end}}</div></header>
{{if .Error}}<div class="panel error">{{.Error}}</div>{{end}}
{{if ne .Mode "dashboard"}}
<div class="grid">
<section class="panel">
<h1>Login</h1>
<form method="post" action="/panel/login"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="primary">Login</button></form>
</section>
<section class="panel">
<h1>Register</h1>
<p class="muted">Create an employee account. Your deploy token will be generated automatically.</p>
<form method="post" action="/panel/register"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary">Create account</button></form>
</section>
</div>
{{else}}
<section class="panel">
<h1>Your servers</h1>
<div class="metric"><div><span class="muted">Servers</span><b>{{len .Servers}}</b></div><div><span class="muted">Deploy Token</span><b>Active</b></div><div><span class="muted">Relay</span><b>bhsocket.io</b></div></div>
</section>
<section class="panel">
<h2>Your deploy command</h2>
<p class="muted">Run this on each remote server. Every deploy with this token appears only in your panel.</p>
<div class="cmd" data-copy="{{.DeployCommand}}"><button class="copy" type="button">Copy</button><pre>{{.DeployCommand}}</pre></div>
<form method="post" action="/panel/token/rotate" style="margin-top:12px"><button>Rotate deploy token</button></form>
</section>
<section class="panel">
<h2>Server list</h2>
<div style="overflow:auto"><table><thead><tr><th>Server</th><th>User</th><th>IP</th><th>Secret</th><th>Connect</th><th>Last deploy</th></tr></thead><tbody>
{{range .Servers}}
<tr><td><strong>{{.Hostname}}</strong><div class="muted">{{.OS}} {{.Arch}}</div><code>{{.InstallPath}}</code></td><td>{{.ServerUser}}</td><td><code>{{if .PublicIP}}{{.PublicIP}}{{else}}{{.IP}}{{end}}</code></td><td class="secret"><code>{{.Secret}}</code></td><td><div class="cmd" data-copy="bh-netcat -s &quot;{{.Secret}}&quot; -i"><button class="copy" type="button">Copy</button><pre>bh-netcat -s "{{.Secret}}" -i</pre></div></td><td>{{.Time.Format "2006-01-02 15:04:05"}}</td></tr>
{{else}}<tr><td colspan="6" class="muted">No servers yet. Run your deploy command on a server.</td></tr>{{end}}
</tbody></table></div>
</section>
{{end}}
</main>
<script>
async function copyText(t){try{await navigator.clipboard.writeText(t)}catch(e){const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()}}
document.querySelectorAll('.cmd').forEach(b=>{const btn=b.querySelector('button');btn.onclick=async()=>{await copyText(b.dataset.copy||b.innerText.trim());btn.textContent='Copied';setTimeout(()=>btn.textContent='Copy',1200)}})
</script>
</body>
</html>`
