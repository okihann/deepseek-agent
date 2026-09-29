package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	defaultRoot string
	allowRoots  []string
	timeout     time.Duration
	authToken   string
)

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
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "data": "invalid root: " + err.Error() + "\n"})
		json.NewEncoder(w).Encode(map[string]any{"type": "exit", "code": -1})
		return
	}

	// Write the user's command to a temp script with an EXIT trap that
	// records the shell's final pwd. This is how cwd persists across
	// commands even when the user runs `cd`.
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

	// Read the final pwd captured by the trap. The client uses this to
	// set the working directory for the next command.
	if data, err := os.ReadFile(cwdFile.Name()); err == nil {
		newCwd := strings.TrimSpace(string(data))
		if newCwd != "" {
			emit(map[string]any{"type": "cwd", "data": newCwd})
		}
	}

	emit(map[string]any{"type": "exit", "code": code})
}

func main() {
	var allowRootsFlag string
	flag.StringVar(&defaultRoot, "root", ".", "default working directory")
	flag.StringVar(&allowRootsFlag, "allow-roots", "", "comma-separated list of allowed client roots (empty = any path)")
	flag.DurationVar(&timeout, "timeout", 5*time.Minute, "per-command timeout")
	flag.StringVar(&authToken, "token", "", "bearer token (empty = no auth)")
	flag.Parse()

	abs, _ := filepath.Abs(defaultRoot)
	defaultRoot = abs

	if allowRootsFlag != "" {
		for _, p := range strings.Split(allowRootsFlag, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			a, _ := filepath.Abs(p)
			allowRoots = append(allowRoots, a)
		}
	}

	log.Printf("default-root=%s allow-roots=%v timeout=%s auth=%v",
		defaultRoot, allowRoots, timeout, authToken != "")

	http.HandleFunc("/exec", handleExec)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		w.Write([]byte("ok"))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
