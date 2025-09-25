package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		want      string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "ok - valid APIKey header",
			headers:   http.Header{"Authorization": []string{"ApiKey a12345"}},
			want:      "a12345",
			wantErr:   false,
			wantErrIs: nil,
		},
		{
			name:      "ok - not Authorization header",
			headers:   http.Header{"X-API-Key": []string{"ApiKey a12345"}},
			want:      "",
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "err - wrong APIKey header",
			headers:   http.Header{"Authorization": []string{"Bearer a12345"}},
			want:      "",
			wantErr:   true,
			wantErrIs: ErrMalformedAuthHeader,
		},
		{
			name: "err - APIKey header without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:      "",
			wantErr:   true,
			wantErrIs: ErrMalformedAuthHeader,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				if !errors.Is(tc.wantErrIs, err) {
					t.Fatalf("expected error: %v, got: %v", tc.wantErrIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}
}
