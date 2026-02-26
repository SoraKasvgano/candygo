package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	cfg "candygo/internal/config"
	"github.com/spf13/pflag"
)

type serviceThread struct {
	done chan struct{}
}

var (
	threadMutex sync.Mutex
	threadMap   = map[string]*serviceThread{}
	apiMutex    sync.Mutex
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func runService(args []string) int {
	fs := pflag.NewFlagSet("candy-service", pflag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	help := fs.BoolP("help", "h", false, "display help information")
	bind := fs.String("bind", "localhost:26817", "bind address and port (address:port)")
	logdir := fs.String("logdir", "", "specify log directory")
	loglevel := fs.String("loglevel", "", "specify log level")
	if err := fs.Parse(args); err != nil {
		fmt.Print(fs.FlagUsages())
		return 1
	}
	if *help {
		fmt.Print(fs.FlagUsages())
		return 0
	}
	if *logdir != "" {
		_ = os.MkdirAll(*logdir, 0o755)
		appLog := filepath.Join(*logdir, "app.log")
		f, err := os.OpenFile(appLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			defer f.Close()
			infof("log file: %s", appLog)
		}
	}
	if *loglevel != "" {
		setDebug(*loglevel == "debug")
	}

	mux := http.NewServeMux()
	// Match C++ service behavior that handles API requests in a single worker thread.
	mux.HandleFunc("/api/run", serializedAPIHandler(serviceRunHandler))
	mux.HandleFunc("/api/status", serializedAPIHandler(serviceStatusHandler))
	mux.HandleFunc("/api/shutdown", serializedAPIHandler(serviceShutdownHandler))

	host, port, err := cfg.RequireBind(*bind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid bind format. Use address:port (e.g., 0.0.0.0:26817): %v\n", err)
		return 1
	}

	server := &http.Server{Addr: fmt.Sprintf("%s:%d", host, port), Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			criticalf("service listen failed: %v", err)
		}
	}()
	infof("bind: %s:%d", host, port)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	infof("exit signal detected")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = server.Shutdown(ctx)
	cancel()

	threadMutex.Lock()
	for id, thread := range threadMap {
		_ = client.shutdown(id)
		<-thread.done
	}
	threadMap = map[string]*serviceThread{}
	threadMutex.Unlock()

	return 0
}

func serializedAPIHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiMutex.Lock()
		defer apiMutex.Unlock()
		next(w, r)
	}
}

func serviceRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		ID     string     `json:"id"`
		Config jsonObject `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonObject{"message": "invalid json"})
		return
	}
	resp := jsonObject{"id": req.ID}

	threadMutex.Lock()
	if _, ok := threadMap[req.ID]; ok {
		resp["message"] = "id already exists"
		threadMutex.Unlock()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	th := &serviceThread{done: make(chan struct{})}
	threadMap[req.ID] = th
	threadMutex.Unlock()

	go func(id string, cfg jsonObject, done chan struct{}) {
		defer close(done)
		_ = client.run(id, cfg)
	}(req.ID, req.Config, th.done)

	resp["message"] = "success"
	writeJSON(w, http.StatusOK, resp)
}

func serviceStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonObject{"message": "invalid json"})
		return
	}
	resp := jsonObject{"id": req.ID}

	threadMutex.Lock()
	if _, exists := threadMap[req.ID]; exists {
		if status, ok := client.status(req.ID); ok {
			resp["status"] = status
			resp["message"] = "success"
		} else {
			resp["message"] = "unable to get status"
		}
	} else {
		resp["message"] = "id does not exist"
	}
	threadMutex.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func serviceShutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonObject{"message": "invalid json"})
		return
	}
	_ = client.shutdown(req.ID)

	resp := jsonObject{"id": req.ID}
	threadMutex.Lock()
	if _, ok := threadMap[req.ID]; ok {
		// C++ service detaches and erases the thread entry immediately.
		delete(threadMap, req.ID)
		resp["message"] = "success"
	} else {
		resp["message"] = "id does not exist"
	}
	threadMutex.Unlock()
	writeJSON(w, http.StatusOK, resp)
}
