//go:build !linux

package processsecurity

import "errors"

var ErrUnsupported = errors.New("secret-process hardening is supported only on Linux")

func HardenSecretProcess() error { return ErrUnsupported }
