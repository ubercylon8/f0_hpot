package sensors

import (
	"log"
	"os"
	"time"
)

// FileWatchSensor watches an existing file (e.g. /etc/shadow, a browser
// cookie store, a keepass db) and alerts when it is read (atime) or
// modified (mtime/size). Poll-based, portable.
//
// Note: reliable read detection requires the filesystem to record atime
// (relatime records first-access-after-mtime, which is usually enough).
type FileWatchSensor struct{}

func (FileWatchSensor) Name() string { return "file_watch" }

func (FileWatchSensor) Start(cfg map[string]interface{}, report Reporter) error {
	path := str(cfg, "path", "")
	if path == "" {
		return logAndErr("file_watch requires 'path'")
	}
	tokenID := str(cfg, "token_id", "")
	label := str(cfg, "label", path)
	interval := time.Duration(intVal(cfg, "interval_seconds", 5)) * time.Second
	watchAtime := true
	if v, ok := cfg["watch_atime"].(bool); ok {
		watchAtime = v
	}

	sig := func() (string, error) {
		st, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		s := st.ModTime().UTC().Format(time.RFC3339Nano)
		if watchAtime {
			s += "|" + atimeOf(st)
		}
		return s, nil
	}

	baseline, err := sig()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cur, err := sig()
		if err != nil {
			continue // transient errors ignored; deletion of watched system file isn't our alert
		}
		if cur != baseline {
			log.Printf("[file_watch] %s changed (%s -> %s)", label, baseline, cur)
			baseline = cur
			report(Trigger{
				Sensor:   "file_watch",
				TokenID:  tokenID,
				Severity: "high",
				Detail: map[string]interface{}{
					"event": "watched_file_accessed",
					"label": label,
					"path":  path,
				},
				SeenAt: time.Now().UTC(),
			})
		}
	}
	return nil
}
