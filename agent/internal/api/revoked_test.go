package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The agent shuts its honeypots down on ErrRevoked and keeps retrying
// through everything else, so the mapping from status code to error has to
// be exact in both directions.
func TestHeartbeatMapsGoneToRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"status":"revoked","message":"agent is no longer registered with this console"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "agt_x", "fdk_x")
	_, _, _, err := c.Heartbeat(nil)
	if err == nil {
		t.Fatal("expected an error for a 410 heartbeat")
	}
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("410 must map to ErrRevoked, got %v", err)
	}
}

func TestHeartbeatDoesNotTreatAuthFailureAsRevocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unknown agent or bad key"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "agt_x", "fdk_x")
	_, _, _, err := c.Heartbeat(nil)
	if err == nil {
		t.Fatal("expected an error for a 401 heartbeat")
	}
	// A 401 may be transient or an orphaned process; decommissioning on it
	// would take down a healthy fleet.
	if errors.Is(err, ErrRevoked) {
		t.Fatalf("401 must NOT be treated as revocation, got %v", err)
	}
}

func TestHeartbeatServerErrorIsNotRevocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"upstream down"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "agt_x", "fdk_x")
	_, _, _, err := c.Heartbeat(nil)
	if err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("a 5xx must be a plain retryable error, got %v", err)
	}
}
