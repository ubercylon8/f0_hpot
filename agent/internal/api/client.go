// Package api implements the agent-side client for the f0_deception API:
// enrollment, heartbeats, and incident reporting over HTTPS/JSON.
package api

import (
	"bytes"
	"encoding/json"
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

// Heartbeat reports liveness and returns current sensor configuration.
func (c *Client) Heartbeat() (pollIntervalSeconds int, sensors []SensorSpec, err error) {
	payload, _ := json.Marshal(map[string]string{"agent_id": c.AgentID})
	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/api/v1/agent/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("authorization", "Bearer "+c.AgentKey)
	req.Header.Set("x-agent-id", c.AgentID)
	req.Header.Set("content-type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("heartbeat: %w", err)
	}
	defer res.Body.Close()

	var out struct {
		PollIntervalSeconds int          `json:"poll_interval_seconds"`
		Sensors             []SensorSpec `json:"sensors"`
		Message             string       `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return 0, nil, fmt.Errorf("heartbeat decode: %w", err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		return 0, nil, fmt.Errorf("heartbeat rejected: %s", out.Message)
	}
	if res.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("heartbeat failed (%d)", res.StatusCode)
	}
	return out.PollIntervalSeconds, out.Sensors, nil
}

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
