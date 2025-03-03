package auth

import (
	"net/http"
	"testing"
)

// Test valid API key retrieval
func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := "my-secret-key"
	if apiKey != expected {
		t.Errorf("Expected %s, got %s", expected, apiKey)
	}
}

// Test missing Authorization header
func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

// Test malformed Authorization header (missing "ApiKey" prefix)
func TestGetAPIKey_MalformedHeader_NoPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key") // Incorrect prefix

	_, err := GetAPIKey(headers)
	expectedErr := "malformed authorization header"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %v", expectedErr, err)
	}
}

// Test malformed Authorization header (only "ApiKey" without key)
func TestGetAPIKey_MalformedHeader_NoKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key") // No key provided

	_, err := GetAPIKey(headers)
	expectedErr := "malformed authorization header"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %v", expectedErr, err)
	}
}
