package infrastructure

import "testing"

func TestNewS3ObjectStoreRequiresSecureOriginUnlessExplicitlyLocalHTTP(t *testing.T) {
	tests := []struct {
		name, endpoint string
		allowHTTP      bool
		wantErr        bool
	}{
		{"missing scheme", "s3.example.test:9000", false, true},
		{"plain HTTP default denied", "http://127.0.0.1:8333", false, true},
		{"URL credentials denied", "https://user:pass@s3.example.test:9000", false, true},
		{"URL path denied", "https://s3.example.test:9000/prefix", false, true},
		{"explicit local HTTP", "http://127.0.0.1:8333", true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewS3ObjectStore(test.endpoint, "recordings", "access", "secret", "", "", "", nil, test.allowHTTP)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewS3ObjectStore error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}
