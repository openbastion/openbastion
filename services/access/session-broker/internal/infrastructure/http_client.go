package infrastructure

import "net/http"

// orDefault is the client a peer's HTTP client uses when none was injected.
func orDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return http.DefaultClient
}
