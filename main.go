package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// -------- config --------

type NgrokCfg struct {
	Enabled   bool   `json:"enabled"`
	Authtoken string `json:"authtoken"`
	Domain    string `json:"domain"`
	DataDir   string `json:"data_dir"`
}

type Config struct {
	Port       int      `json:"port"`
	Root       string   `json:"root"`
	AllowRoots []string `json:"allow_roots"`
	Timeout    string   `json:"timeout"`
	Token      string   `json:"token"`
	Ngrok      NgrokCfg `json:"ngrok"`
}

func defaultConfig() Config {
	return Config{
		Port:       8080,
		Root:       ".",
		AllowRoots: []string{},
		Timeout:    "5m",
		Token:      "",
		Ngrok: NgrokCfg{
			Enabled:   false,
			Authtoken: "",
			Domain:    "",
			DataDir:   "./.ngrok",
		},
	}
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	c = defaultConfig()
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

func writeDefaultConfig(path string) error {
	data, err := json.MarshalIndent(defaultConfig(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "config.json")
	}
	return "config.json"
}

// -------- runtime state --------

var (
	cfg         Config
	timeout     time.Duration
	defaultRoot string
	allowRoots  []string
	authToken   string

	ngrokURL string
	ngrokMu  sync.RWMutex
	ngrokCmd *exec.Cmd
)

// ngrok's local inspection API. Default port is 4040 and is not
// configurable via CLI flag in ngrok v3 -- only via config file.
const ngrokWebAddr = "127.0.0.1:4040"

// -------- HTTP helpers --------

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
}

type execRequest struct {
	Command string `json:"command"`
	Root    string `json:"root,omitempty"`
}

func resolveRoot(clientRoot string) (string, error) {
	root := strings.TrimSpace(clientRoot)
	if root == "" {
		return defaultRoot, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if len(allowRoots) > 0 {
		ok := false
		for _, allowed := range allowRoots {
			if abs == allowed || strings.HasPrefix(abs, allowed+string(os.PathSeparator)) {
				ok = true
				break
			}
		}
		if !ok {
			return "", os.ErrPermission
		}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", os.ErrInvalid
	}
	return abs, nil
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if authToken != "" && r.Header.Get("Authorization") != "Bearer "+authToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	workDir, err := resolveRoot(req.Root)
	if err != nil {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "data": "invalid root: " + err.Error() + "\n"})
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "exit", "code": -1})
		return
	}

	tmpScript, err := os.CreateTemp("", "cuckoo-*.sh")
	if err != nil {
		http.Error(w, "temp: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpScript.Name())

	cwdFile, err := os.CreateTemp("", "cuckoo-cwd-*")
	if err != nil {
		http.Error(w, "temp: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cwdFile.Close()
	defer os.Remove(cwdFile.Name())

	prelude := `trap '__ck_rc=$?; pwd > "$__CUCKOO_CWD_FILE" 2>/dev/null; exit $__ck_rc' EXIT
`
	if _, err := tmpScript.WriteString(prelude + req.Command + "\n"); err != nil {
		http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpScript.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)

	var writeMu sync.Mutex
	emit := func(v any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = enc.Encode(v)
		if flusher != nil {
			flusher.Flush()
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", tmpScript.Name())
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"CUCKOO=1",
		"__CUCKOO_CWD_FILE="+cwdFile.Name(),
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		emit(map[string]any{"type": "error", "data": err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		emit(map[string]any{"type": "error", "data": err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		emit(map[string]any{"type": "error", "data": err.Error()})
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	stream := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			emit(map[string]any{"type": "output", "data": sc.Text() + "\n"})
		}
	}
	go stream(stdout)
	go stream(stderr)
	wg.Wait()

	code := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		emit(map[string]any{"type": "error", "data": "timeout\n"})
	}

	if data, err := os.ReadFile(cwdFile.Name()); err == nil {
		newCwd := strings.TrimSpace(string(data))
		if newCwd != "" {
			emit(map[string]any{"type": "cwd", "data": newCwd})
		}
	}

	emit(map[string]any{"type": "exit", "code": code})
}

// -------- ngrok --------

func ngrokBinaryName() string {
	if runtime.GOOS == "windows" {
		return "ngrok.exe"
	}
	return "ngrok"
}

func ngrokDownloadURL() (string, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	var ext string
	switch osName {
	case "linux", "darwin":
		ext = "tgz"
	case "windows":
		ext = "zip"
	default:
		return "", fmt.Errorf("unsupported OS for ngrok: %s", osName)
	}

	switch arch {
	case "amd64", "arm64", "386":
	default:
		return "", fmt.Errorf("unsupported arch for ngrok: %s", arch)
	}

	return fmt.Sprintf(
		"https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-%s-%s.%s",
		osName, arch, ext,
	), nil
}

func extractTarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(dest, filepath.Base(hdr.Name))
		of, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(of, tr); err != nil {
			of.Close()
			return err
		}
		of.Close()
	}
	return nil
}

func extractZip(archive, dest string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		out := filepath.Join(dest, filepath.Base(f.Name))
		rc, err := f.Open()
		if err != nil {
			return err
		}
		of, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(of, rc); err != nil {
			of.Close()
			rc.Close()
			return err
		}
		of.Close()
		rc.Close()
	}
	return nil
}

// ensureNgrok downloads & extracts the ngrok binary into dir (if not present).
func ensureNgrok(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(dir, ngrokBinaryName())
	if st, err := os.Stat(binPath); err == nil && st.Size() > 0 {
		log.Printf("ngrok: using cached binary %s", binPath)
		return binPath, nil
	}

	url, err := ngrokDownloadURL()
	if err != nil {
		return "", err
	}
	log.Printf("ngrok: downloading %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ngrok download failed: %s", resp.Status)
	}

	tmp, err := os.CreateTemp("", "ngrok-archive-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	if runtime.GOOS == "windows" {
		if err := extractZip(tmp.Name(), dir); err != nil {
			return "", err
		}
	} else {
		if err := extractTarGz(tmp.Name(), dir); err != nil {
			return "", err
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(binPath, 0o755); err != nil {
			return "", err
		}
	}
	log.Printf("ngrok: installed %s", binPath)
	return binPath, nil
}

// startNgrok launches `ngrok http <port> --authtoken ... [--domain ...]`.
// Note: ngrok v3 has no --web-addr flag; the inspection UI is fixed at
// 127.0.0.1:4040 unless configured via a config file. We use the default.
func startNgrok(binPath string, port int, token, domain string) (*exec.Cmd, error) {
	args := []string{
		"http", fmt.Sprintf("%d", port),
		"--authtoken", token,
		"--log", "stdout",
		"--log-level", "warn",
	}
	if domain != "" {
		args = append(args, "--domain", domain)
	}

	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// pollNgrokURL queries the local ngrok API until the public URL is known.
func pollNgrokURL(ctx context.Context) {
	type tunnel struct {
		PublicURL string `json:"public_url"`
		Proto     string `json:"proto"`
	}
	type apiResp struct {
		Tunnels []tunnel `json:"tunnels"`
	}

	client := &http.Client{Timeout: 3 * time.Second}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	apiURL := "http://" + ngrokWebAddr + "/api/tunnels"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		resp, err := client.Get(apiURL)
		if err != nil {
			continue
		}
		var ar apiResp
		decErr := json.NewDecoder(resp.Body).Decode(&ar)
		resp.Body.Close()
		if decErr != nil {
			continue
		}

		// Prefer https; fall back to the first tunnel.
		var pick string
		for _, t := range ar.Tunnels {
			if strings.HasPrefix(t.PublicURL, "https://") {
				pick = t.PublicURL
				break
			}
			if pick == "" {
				pick = t.PublicURL
			}
		}
		if pick == "" {
			continue
		}

		ngrokMu.Lock()
		if ngrokURL != pick {
			ngrokURL = pick
			log.Printf("ngrok: public url = %s", pick)
		}
		ngrokMu.Unlock()
	}
}

func handleNgrokInfo(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if authToken != "" && r.Header.Get("Authorization") != "Bearer "+authToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ngrokMu.RLock()
	u := ngrokURL
	ngrokMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled": cfg.Ngrok.Enabled,
		"url":     u,
		"port":    cfg.Port,
		"domain":  cfg.Ngrok.Domain,
	})
}

// -------- main --------

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to config.json")
	flag.Parse()

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if err := writeDefaultConfig(*configPath); err != nil {
			log.Fatalf("write default config: %v", err)
		}
		log.Printf("wrote default config to %s", *configPath)
		log.Printf("edit it (set root, token, ngrok.authtoken, ...) then run ./cuckoo again")
		return
	}

	loaded, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg = loaded

	// timeout
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			log.Fatalf("bad timeout %q: %v", cfg.Timeout, err)
		}
		timeout = d
	} else {
		timeout = 5 * time.Minute
	}

	// root
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		log.Fatalf("bad root %q: %v", cfg.Root, err)
	}
	defaultRoot = abs

	// allow-roots
	for _, p := range cfg.AllowRoots {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, err := filepath.Abs(p)
		if err != nil {
			log.Fatalf("bad allow_root %q: %v", p, err)
		}
		allowRoots = append(allowRoots, a)
	}

	authToken = cfg.Token

	log.Printf("config=%s port=%d root=%s allow=%v timeout=%s auth=%v ngrok=%v",
		*configPath, cfg.Port, defaultRoot, allowRoots, timeout, authToken != "", cfg.Ngrok.Enabled)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if cfg.Ngrok.Enabled {
		if cfg.Ngrok.Authtoken == "" {
			log.Fatal("ngrok.enabled=true but ngrok.authtoken is empty")
		}

		binPath, err := ensureNgrok(cfg.Ngrok.DataDir)
		if err != nil {
			log.Fatalf("ngrok: %v", err)
		}

		cmd, err := startNgrok(binPath, cfg.Port, cfg.Ngrok.Authtoken, cfg.Ngrok.Domain)
		if err != nil {
			log.Fatalf("ngrok start: %v", err)
		}
		ngrokCmd = cmd

		go pollNgrokURL(ctx)
		go func() {
			<-ctx.Done()
			if ngrokCmd != nil && ngrokCmd.Process != nil {
				log.Printf("ngrok: shutting down")
				_ = ngrokCmd.Process.Signal(syscall.SIGTERM)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/exec", handleExec)
	mux.HandleFunc("/ngrok", handleNgrokInfo)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("listening on :%d", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
