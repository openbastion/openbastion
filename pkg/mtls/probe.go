package mtls

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ProbeSelf asks the running service, on 127.0.0.1:port and path, whether it is up, as the service
// itself: under its own identity, expecting its own on the other side (a healthcheck in an image
// with no shell, ADR-0072). Nil means a 200. Only a path of the service's own, on the loopback.
func ProbeSelf(ctx context.Context, service string, port int, path string) error {
	if port < 1 || port > 65535 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("mtls: probe of %s: port %d or path %q not usable", service, port, path)
	}
	rt, err := Setup(service)
	if err != nil {
		return err
	}
	base := rt.DefaultURL(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	client, err := rt.Client(Peer{URL: base, Service: service})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: probe %s: %w", service, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: probe %s: status %d", service, path, resp.StatusCode)
	}
	return nil
}
