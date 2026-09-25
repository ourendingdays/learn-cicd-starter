package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   bool
		wantErrIs error // for checking a specific error; nil if we don't care which one
	}{
		{
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: false,
		},
		{
			name:      "no Authorization header",
			headers:   http.Header{},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "wrong scheme (Bearer instead of ApiKey)",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantErr: true,
		},
		{
			name:    "ApiKey with no key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.headers)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("expected error %v, got %v", tc.wantErrIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKey != tc.wantKey {
				t.Errorf("expected key %q, got %q", tc.wantKey, gotKey)
			}
		})
	}
}
