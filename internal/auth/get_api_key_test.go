package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if apiKey != "my-secret-key" {
		t.Errorf("expected api key %q, got %q", "my-secret-key", apiKey)
	}
}

func TestGetAPIKey_NoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key")

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	if err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header, got %v", err)
	}
}