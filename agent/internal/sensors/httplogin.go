package sensors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPLoginSensor serves a fake admin login page on a port. Any POST to
// /login (or any request, optionally) is reported as a high-severity hit.
type HTTPLoginSensor struct{}

func (HTTPLoginSensor) Name() string { return "http_login" }

func str(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key].(string); ok && v != "" {
		return v
	}
	return def
}

func intVal(cfg map[string]interface{}, key string, def int) int {
	if v, ok := cfg[key].(float64); ok {
		return int(v)
	}
	return def
}

func (HTTPLoginSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 8081)
	tokenID := str(cfg, "token_id", "")
	appName := str(cfg, "app_name", "Router Admin")
	alertAll := false
	if v, ok := cfg["alert_on_get"].(bool); ok {
		alertAll = v
	}

	mux := http.NewServeMux()
	page := fmt.Sprintf(`<!doctype html><html><head><title>%s Login</title></head>
<body style="font-family:sans-serif;max-width:360px;margin:80px auto">
<h2>%s</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username" style="width:100%%;padding:8px;margin-bottom:8px"><br>
<input name="password" type="password" placeholder="Password" style="width:100%%;padding:8px;margin-bottom:8px"><br>
<button style="padding:8px 16px">Sign in</button>
</form></body></html>`, appName, appName)

	reportHit := func(detail map[string]interface{}) {
		report(Trigger{
			Sensor:   "http_login",
			TokenID:  tokenID,
			Severity: "high",
			Detail:   detail,
			SeenAt:   time.Now().UTC(),
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		detail := baseDetail(r)
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/login") {
			_ = r.ParseForm()
			u := r.PostFormValue("username")
			p := r.PostFormValue("password")
			detail["username"] = u
			detail["password_len"] = len(p)
			log.Printf("[http_login] cred attempt user=%q pass_len=%d from %s", u, len(p), detail["source_ip"])
			reportHit(detail)
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if alertAll {
			reportHit(detail)
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	log.Printf("[http_login] serving fake %q login on :%d", appName, port)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.ListenAndServe()
	if ctx.Err() != nil {
		log.Printf("[http_login] stopped")
		return nil
	}
	return err
}

func baseDetail(r *http.Request) map[string]interface{} {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return map[string]interface{}{
		"method":     r.Method,
		"path":       r.URL.Path,
		"user_agent": r.UserAgent(),
		"source_ip":  ip,
	}
}

// randomHex is a tiny helper for future session-bait identifiers.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var _ = randomHex // keep until used
