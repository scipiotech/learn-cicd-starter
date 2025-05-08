package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "Valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey: "abc123",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: nil,
		},
		{
			name:    "Malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed header - only one part",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed header - empty string",
			headers: http.Header{"Authorization": []string{""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			if (err == nil) != (tt.wantErr == nil) || (err != nil && err.Error() != tt.wantErr.Error()) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}
