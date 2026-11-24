package dbpool

import "testing"

func TestParseEnvDefaultsAndIdleClamp(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
		want Config
	}{
		{name: "defaults", want: Config{MaxOpenConns: 10, MaxIdleConns: 10}},
		{
			name: "open below default clamps idle",
			vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "3"},
			want: Config{MaxOpenConns: 3, MaxIdleConns: 3},
		},
		{
			name: "explicit idle zero",
			vars: map[string]string{"DB_POOL_MAX_IDLE_CONNS": "0"},
			want: Config{MaxOpenConns: 10, MaxIdleConns: 0},
		},
		{
			name: "explicit limits",
			vars: map[string]string{
				"DB_POOL_MAX_OPEN_CONNS": "25",
				"DB_POOL_MAX_IDLE_CONNS": "7",
			},
			want: Config{MaxOpenConns: 25, MaxIdleConns: 7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEnv(func(key string) (string, bool) {
				value, ok := tt.vars[key]
				return value, ok
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseEnvRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
	}{
		{name: "empty open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": ""}},
		{name: "zero open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "0"}},
		{name: "negative open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "-1"}},
		{name: "signed open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "+10"}},
		{name: "whitespace open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": " 10"}},
		{name: "fractional open", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "1.5"}},
		{name: "open above maximum", vars: map[string]string{"DB_POOL_MAX_OPEN_CONNS": "1001"}},
		{
			name: "idle above open",
			vars: map[string]string{
				"DB_POOL_MAX_OPEN_CONNS": "5",
				"DB_POOL_MAX_IDLE_CONNS": "6",
			},
		},
		{name: "negative idle", vars: map[string]string{"DB_POOL_MAX_IDLE_CONNS": "-1"}},
		{name: "empty idle", vars: map[string]string{"DB_POOL_MAX_IDLE_CONNS": ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEnv(func(key string) (string, bool) {
				value, ok := tt.vars[key]
				return value, ok
			})
			if err == nil {
				t.Fatal("accepted invalid value")
			}
		})
	}
}
