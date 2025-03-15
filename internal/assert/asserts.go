package assert

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Equal compares two values
func Equal[T comparable](t *testing.T, actual, expected T) {
	t.Helper()

	// Log an error if the test does not pass the Equal test
	if actual != expected {
		t.Errorf("got: %v; not: %v", actual, expected)
	}
}

// NoError asserts that the given error is nil
func NoError(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err != nil {
		message := "Expected no error, but got an error"
		if len(msgAndArgs) > 0 {
			message = fmt.Sprintf("%s: %s", message, fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		}
		t.Errorf("%s\nError: %v", message, err)
	}
}

// EqualSlices compares two slices of any comparable type for equality
func EqualSlices[T comparable](t *testing.T, actual, expected []T) {
	t.Helper()
	// Compare the length of the slices for equality
	if len(actual) != len(expected) {
		t.Errorf("slice length mismatch: got %d elements; want %d elements", len(actual), len(expected))
		t.Errorf("got: %v; want: %v", actual, expected)
		return
	}

	for i := range actual {
		if actual[i] != expected[i] {
			t.Errorf("mismatch at index %d: got %v; want %v", i, actual[i], expected[i])
		}
	}
}

// StringContains tests if a string contains a specified substring
func StringContains(t *testing.T, actual, expectedSubstring string) {
	t.Helper()

	if !strings.Contains(actual, expectedSubstring) {
		t.Errorf("got %q; expected to contain: %q", actual, expectedSubstring)
	}
}

// StringNotContains tests that the string does not contain a specified substring
func StringNotContains(t *testing.T, actual, expectedSubstring string) {
	t.Helper()

	if strings.Contains(actual, expectedSubstring) {
		t.Errorf("got %q; expected to NOT contain: %q", actual, expectedSubstring)
	}
}

// EqualTime tests if the time is equal (times are within 1s of each other)
func EqualTime(t *testing.T, actual, expected time.Time) {
	t.Helper()
	dif := actual.Sub(expected).Abs()

	if dif > time.Second {
		t.Errorf("got %v; not %v; off by %v", actual, expected, dif.Minutes())
	}
}
