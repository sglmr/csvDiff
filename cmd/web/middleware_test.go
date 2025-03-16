package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
)

func TestSecureHeadersMW(t *testing.T) {
	t.Parallel()

	// Initialize a new httptest.ResponseRecorder and dummy http.Request.
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock HTTP handler that we can pass to our SecureHeadersMW
	// middleware, which writes a 200 status code and an "OK" response body.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Pass the mock HTTP handler to the SecureHeadersMW middleware.
	// Call ServeHTTP to execute it.
	SecureHeadersMW(next).ServeHTTP(rr, r)

	// Get the results of the test
	rs := rr.Result()

	// Check that the middleware has correctly set the Referrer-Policy
	// header on the response.
	want := "origin-when-cross-origin"
	assert.Equal(t, rs.Header.Get("Referrer-Policy"), want)

	// Check that the middleware has correctly set the X-Content-Type-Options
	// header on the response.
	want = "nosniff"
	assert.Equal(t, rs.Header.Get("X-Content-Type-Options"), want)

	// Check that the middleware has correctly set the X-Frame-Options header
	// on the response.
	want = "deny"
	assert.Equal(t, rs.Header.Get("X-Frame-Options"), want)

	// Check that the middleware has correctly set the X-XSS-Protection header
	// on the response
	want = "0"
	assert.Equal(t, rs.Header.Get("X-XSS-Protection"), want)

	// Check that the middleware has correctly called the next handler in line
	// and the response status code and body are as expected.
	assert.Equal(t, rs.StatusCode, http.StatusOK)

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.TrimSpace(body)

	assert.Equal(t, string(body), "OK")
}
