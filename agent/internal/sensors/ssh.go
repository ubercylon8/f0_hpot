package sensors

import (
	"context"
	"fmt"
	"log"
	"time"

	glssh "github.com/gliderlabs/ssh"
)

// SSHSensor runs a low-interaction SSH honeypot: accepts any
// password-authenticated login, captures credentials and commands, and
// answers every command with a plausible empty result.
type SSHSensor struct{}

func (SSHSensor) Name() string { return "ssh" }

func (SSHSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 2222)
	tokenID := str(cfg, "token_id", "")
	banner := str(cfg, "banner", "SSH-2.0-OpenSSH_9.6")

	reporter := func(session glssh.Session) {
		cmd := session.Command()
		detail := map[string]interface{}{
			"event":     "command_execution",
			"user":      session.User(),
			"command":   cmd,
			"source_ip": session.RemoteAddr().String(),
			"env":       session.Environ(),
		}
		log.Printf("[ssh] user=%q cmd=%q from %s", session.User(), cmd, detail["source_ip"])
		report(Trigger{
			Sensor:   "ssh",
			TokenID:  tokenID,
			Severity: "high",
			Detail:   detail,
			SeenAt:   time.Now().UTC(),
		})
		// Plausible no-op output so interactive attackers keep typing.
		if len(cmd) > 0 {
			fmt.Fprintln(session, "")
		}
	}

	server := &glssh.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: reporter,
		Version: banner,
		PasswordHandler: func(ctx glssh.Context, password string) bool {
			detail := map[string]interface{}{
				"event":          "credential_attempt",
				"user":           ctx.User(),
				"password":       password,
				"source_ip":      ctx.RemoteAddr().String(),
				"auth":           "password",
				"client_version": ctx.ClientVersion(),
			}
			log.Printf("[ssh] cred attempt user=%q pass=%q from %s", ctx.User(), password, ctx.RemoteAddr())
			report(Trigger{
				Sensor:   "ssh",
				TokenID:  tokenID,
				Severity: "high",
				Detail:   detail,
				SeenAt:   time.Now().UTC(),
			})
			return true // accept everyone; this IS the honeypot
		},
	}

	log.Printf("[ssh] listening on :%d (accepts all credentials)", port)
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	err := server.ListenAndServe()
	if ctx.Err() != nil {
		log.Printf("[ssh] stopped")
		return nil
	}
	return err
}
