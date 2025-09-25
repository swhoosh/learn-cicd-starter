package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr bool
	}{
		{
			name:    "ok - valid APIKey header",
			headers: http.Header{"Authorization": []string{"ApiKey a12345"}},
			want:    "a12345",
			wantErr: false,
		},
		{
			name:    "ok - not Authorization header",
			headers: http.Header{"X-API-Key": []string{"a12345"}},
			want:    "",
			wantErr: true,
		},
		{
			name:    "err - wrong APIKey header",
			headers: http.Header{"Authorization": []string{"Bearer a12345"}},
			want:    "",
			wantErr: true,
		},
		{
			name: "err - APIKey header malformed",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
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
