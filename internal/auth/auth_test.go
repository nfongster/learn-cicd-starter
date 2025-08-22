package auth

import (
	"fmt"
	"net/http"
	"testing"
)

func TestAPIKey(t *testing.T) {
	header := make(http.Header)
	expectedKey := "my-test-key"
	header.Set("Authorization", fmt.Sprintf("ApiKey %s", expectedKey))

	actualKey, err := GetAPIKey(header)
	if err != nil {
		t.Errorf("error when getting api key: %v", err)
	}
	if actualKey != expectedKey {
		t.Errorf("actual key (%s) did not match expected key (%s)", actualKey, expectedKey)
	}
}

func TestAPIKeyNoHeader(t *testing.T) {
	header := make(http.Header)

	if _, err := GetAPIKey(header); err == nil {
		t.Errorf("expected error from empty header, but got no error")
	}
}

func TestAPIKeyMalformedHeader(t *testing.T) {
	header := make(http.Header)
	expectedKey := "my-test-key"
	header.Set("Authorization", expectedKey)

	if _, err := GetAPIKey(header); err == nil {
		t.Errorf("expected error from malformed header, but got no error")
	}
}

func TestAPIKeyMissingKey(t *testing.T) {
	header := make(http.Header)
	header.Set("Authorization", "ApiKey")

	if _, err := GetAPIKey(header); err == nil {
		t.Errorf("expected error from header with no key, but got no error")
	}
}
