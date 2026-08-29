package sensors

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PlantedCredentialSensor drops a bait credentials file (e.g. a fake
// "passwords.txt" or .env) on disk and polls its atime/mtime. Any access
// is reported as a high-severity hit.
//
// v1 uses polling (portable, no syscalls/ETW); atime depends on the
// filesystem being mounted with relatime/strictatime — mtime catches
// modification, ctime catches metadata tampering.
type PlantedCredentialSensor struct{}

func (PlantedCredentialSensor) Name() string { return "planted_credential" }

func (PlantedCredentialSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	path := str(cfg, "path", "")
	if path == "" {
		return logAndErr("planted_credential requires 'path'")
	}
	tokenID := str(cfg, "token_id", "")
	label := str(cfg, "label", path)
	interval := time.Duration(intVal(cfg, "interval_seconds", 5)) * time.Second

	content := str(cfg, "content", defaultBaitContent(label))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
		// Backdate mtime so relatime mounts (the Linux default) will
		// update atime on the very next read: relatime refreshes atime
		// only when it is older than mtime.
		old := time.Now().Add(-48 * time.Hour)
		_ = os.Chtimes(path, old, old)
		log.Printf("[planted_credential] planted bait at %s", path)
	}

	baseline, err := statSignature(path)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		cur, err := statSignature(path)
		if err != nil {
			if os.IsNotExist(err) {
				report(Trigger{
					Sensor:   "planted_credential",
					TokenID:  tokenID,
					Severity: "high",
					Detail:   map[string]interface{}{"event": "bait_file_deleted", "label": label, "path": path},
					SeenAt:   time.Now().UTC(),
				})
				return nil // bait gone; sensor stops (operator should re-plant)
			}
			continue
		}
		if cur != baseline {
			// mtime unchanged but the signature moved => the file was read,
			// not written. Worth distinguishing: a read is the classic
			// credential-harvesting signal, a write is tampering.
			access := "bait_file_read"
			if mtimePart(cur) != mtimePart(baseline) {
				access = "bait_file_modified"
			}
			detail := map[string]interface{}{
				"event":  "bait_file_touched",
				"access": access,
				"label":  label,
				"path":   path,
				"before": baseline,
				"after":  cur,
			}
			log.Printf("[planted_credential] %s %s (%s -> %s)", label, access, baseline, cur)
			baseline = cur
			report(Trigger{
				Sensor:   "planted_credential",
				TokenID:  tokenID,
				Severity: "high",
				Detail:   detail,
				SeenAt:   time.Now().UTC(),
			})
		}
	}
}

// statSignature covers access time as well as modification time: the point
// of a planted credential is to catch someone *reading* it, and a read moves
// only atime. (The sensor backdates atime when planting so the first read
// registers even under relatime.) Where atime is unavailable — Windows, or a
// noatime mount — atimeOf returns "" and this degrades to mtime-only.
func statSignature(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return st.ModTime().UTC().Format(time.RFC3339Nano) + "|" + atimeOf(st), nil
}

func defaultBaitContent(label string) string {
	return "# " + label + "\n" +
		"# DO NOT SHARE\n" +
		"vpn.corp.example.com: admin / Summer2026!\n" +
		"jira.corp.example.com: svc-backup / Xk9#mP2$vL8q\n" +
		"db-primary: postgres / Zr4!nW7@bF1d\n"
}

func logAndErr(msg string) error {
	log.Printf("config error: %s", msg)
	return errConfig(msg)
}

type configError string

func (e configError) Error() string { return string(e) }

func errConfig(msg string) error { return configError(msg) }

// mtimePart returns the modification-time half of a statSignature.
func mtimePart(sig string) string {
	if i := strings.IndexByte(sig, '|'); i >= 0 {
		return sig[:i]
	}
	return sig
}
