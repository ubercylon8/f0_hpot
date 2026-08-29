// Package api implements the agent-side client for the f0_deception API:
// enrollment, heartbeats, and incident reporting over HTTPS/JSON.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const httpTimeout = 15 * time.Second

type Client struct {
	ServerURL string
	AgentID   string
	AgentKey  string
	http      *http.Client
}

func New(serverURL, agentID, agentKey string) *Client {
	return &Client{
		ServerURL: serverURL,
		AgentID:   agentID,
		AgentKey:  agentKey,
		http:      &http.Client{Timeout: httpTimeout},
	}
}

// Enroll exchanges a one-time enrollment token for a persistent identity.
func Enroll(serverURL, enrollmentToken, hostname, platform, version string) (agentID, agentKey string, err error) {
	payload, _ := json.Marshal(map[string]string{
		"enrollment_token": enrollmentToken,
		"hostname":         hostname,
		"platform":         platform,
		"version":          version,
	})
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/agent/enroll", bytes.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	res, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}
	defer res.Body.Close()

	var out struct {
		AgentID  string `json:"agent_id"`
		AgentKey string `json:"agent_key"`
		Error    string `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("enroll decode: %w", err)
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return "", "", fmt.Errorf("enroll failed (%d): %s", res.StatusCode, out.Error)
	}
	return out.AgentID, out.AgentKey, nil
}

// SensorSpec describes one honeypot/sensor the agent should run.
type SensorSpec struct {
	Kind    string                 `json:"kind"`
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// Deployment is a one-shot token deployment delivered via heartbeat:
// plant an artifact file or a URL shortcut on this host.
type Deployment struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"` // file | shortcut
	TargetDir string  `json:"targetDir"`
	Filename  string  `json:"filename"`
	Payload   *string `json:"payload"` // base64 file bytes (file kind)
	URL       *string `json:"url"`     // trigger URL (shortcut kind)
}

// DeploymentResult reports the outcome of executing a Deployment; sent
// on a later heartbeat (never in the same one it was received).
type DeploymentResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Heartbeat reports liveness (plus any deployment results from previous
// work) and returns current sensor configuration and pending deployments.
func (c *Client) Heartbeat(results []DeploymentResult) (pollIntervalSeconds int, sensors []SensorSpec, deployments []Deployment, err error) {
	body := map[string]interface{}{"agent_id": c.AgentID}
	if len(results) > 0 {
		body["deployment_results"] = results
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/api/v1/agent/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("authorization", "Bearer "+c.AgentKey)
	req.Header.Set("x-agent-id", c.AgentID)
	req.Header.Set("content-type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("heartbeat: %w", err)
	}
	defer res.Body.Close()

	var out struct {
		PollIntervalSeconds int          `json:"poll_interval_seconds"`
		Sensors             []SensorSpec `json:"sensors"`
		Deployments         []Deployment `json:"deployments"`
		Message             string       `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return 0, nil, nil, fmt.Errorf("heartbeat decode: %w", err)
	}
	// 410 is the console saying this agent was retired — a definitive,
	// non-transient answer the caller must not retry through.
	if res.StatusCode == http.StatusGone {
		return 0, nil, nil, fmt.Errorf("%w: %s", ErrRevoked, out.Message)
	}
	if res.StatusCode == http.StatusUnauthorized {
		return 0, nil, nil, fmt.Errorf("heartbeat rejected: %s", out.Message)
	}
	if res.StatusCode != http.StatusOK {
		return 0, nil, nil, fmt.Errorf("heartbeat failed (%d)", res.StatusCode)
	}
	return out.PollIntervalSeconds, out.Sensors, out.Deployments, nil
}

// ErrRevoked means the console no longer knows this agent: it was retired
// from the fleet. Distinct from an auth failure, which may be transient or
// an orphaned process, and which the agent keeps retrying through.
var ErrRevoked = errors.New("agent revoked")

// Incident is the reportable trigger event. It reuses the gateway's
// incident ingestion endpoint so all detections flow through one pipeline.
type Incident struct {
	TokenID  string      `json:"tokenId"`
	Severity string      `json:"severity"`
	Event    interface{} `json:"event"`
}

func (c *Client) ReportIncident(inc Incident) error {
	payload, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/api/v1/incidents", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+c.AgentKey)
	req.Header.Set("x-agent-id", c.AgentID)
	req.Header.Set("content-type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("incident report failed (%d)", res.StatusCode)
	}
	return nil
}
