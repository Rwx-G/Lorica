package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "80"
	}
	backendID := os.Getenv("BACKEND_ID")
	if backendID == "" {
		backendID = "backend-h2"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Id", backendID)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backend":  backendID,
			"path":     r.URL.Path,
			"method":   r.Method,
			"protocol": r.Proto,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"backend": backendID,
		})
	})

	// h2c server: speaks HTTP/2 over cleartext (no TLS)
	h2s := &http2.Server{}
	handler := h2c.NewHandler(mux, h2s)

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	fmt.Printf("Backend %s listening on h2c port %s\n", backendID, port)
	if err := http.ListenAndServe(addr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
