package infrastructure

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func TestNewVideoRecorderGRPCClient_RequiresExplicitDevelopmentTransport(t *testing.T) {
	runtime, err := mtls.SetupWith(mtls.APIGateway, mtls.Settings{Mode: mtls.Disabled})
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewVideoRecorderGRPCClient(runtime, "http://video-recorder:8089")
	if err != nil {
		t.Fatalf("development-mode client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("closing client: %v", err)
	}

	for _, endpoint := range []string{
		"https://video-recorder:8089",
		"http://user:password@video-recorder:8089",
		"http://video-recorder:8089/path",
		"http://video-recorder:8089?token=secret",
	} {
		if client, err := NewVideoRecorderGRPCClient(runtime, endpoint); err == nil {
			_ = client.Close()
			t.Errorf("endpoint %q was accepted in development mode", endpoint)
		}
	}
}

func TestNewVideoRecorderGRPCClient_RequiresRuntimeAndEndpoint(t *testing.T) {
	if _, err := NewVideoRecorderGRPCClient(nil, "http://video-recorder:8089"); err == nil {
		t.Fatal("a nil mTLS runtime was accepted")
	}
	runtime, err := mtls.SetupWith(mtls.APIGateway, mtls.Settings{Mode: mtls.Disabled})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"", "video-recorder:8089", "http://", "ftp://video-recorder:8089"} {
		if client, err := NewVideoRecorderGRPCClient(runtime, endpoint); err == nil {
			_ = client.Close()
			t.Errorf("invalid endpoint %q was accepted", endpoint)
		}
	}
}
