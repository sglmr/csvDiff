package main

import (
	"net/http"
	"testing"

	"github.com/sglmr/csvdiff/internal/assert"
	"github.com/sglmr/csvdiff/internal/vcs"
)

func TestHealth(t *testing.T) {
	t.Parallel()

	ts := newTestServer(t)
	defer ts.Close()

	response := ts.get(t, "/health/")

	// Check that the status code was 200.
	assert.Equal(t, http.StatusOK, response.statusCode)

	// Check the content type
	assert.Equal(t, response.header.Get("Content-Type"), "text/plain")

	// Check the body contains "OK"
	assert.StringContains(t, response.body, "status: OK")
	assert.StringContains(t, response.body, vcs.Version())
}

func TestHome(t *testing.T) {
	t.Parallel()

	ts := newTestServer(t)
	defer ts.Close()

	response := ts.get(t, "/")

	assert.Equal(t, http.StatusOK, response.statusCode)
	assert.StringContains(t, response.body, "Diff")
}
