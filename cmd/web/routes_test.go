package main

import (
	"net/http"
	"net/url"
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

func TestContactE2E(t *testing.T) {
	t.Parallel()

	// Create a new test server
	ts := newTestServer(t)
	defer ts.Close()

	// ------- Test GET Method ---------

	response := ts.get(t, "/contact/")
	token := response.csrfToken(t)

	// Check the status of the request
	assert.Equal(t, response.statusCode, http.StatusOK)

	// Check that the body contains the word "contact"
	assert.StringContains(t, response.body, "Contact")

	// -------- Test Post without CSRF --------------------

	data := url.Values{}
	data.Add("name", "joe")
	data.Add("email", "joe@example.com")
	data.Add("message", "some message")

	// Create a new http POST request.
	response = ts.post(t, "/contact/", data)

	// Bad request because
	assert.Equal(t, response.statusCode, http.StatusBadRequest)

	// --------- Test POST with CSRF -----------------

	// Add the csrf_token to the request
	data.Add("csrf_token", token)

	// Create a new http POST request.
	response = ts.post(t, "/contact/", data)

	assert.Equal(t, response.statusCode, http.StatusFound)
}

func TestHome(t *testing.T) {
	t.Parallel()

	ts := newTestServer(t)
	defer ts.Close()

	response := ts.get(t, "/")

	assert.Equal(t, http.StatusOK, response.statusCode)
	assert.StringContains(t, response.body, "Example")
}
