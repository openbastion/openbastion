package application_test

import (
	"context"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
)

type fakeMFAActionClient struct {
	grant          application.MFAActionGrant
	verifyBinding  application.MFAActionBinding
	consumeBinding application.MFAActionBinding
	consumedGrant  string
	onVerify       func()
}

func (f *fakeMFAActionClient) Start(context.Context, application.MFAActionBinding) (application.MFAActionStart, error) {
	return application.MFAActionStart{Challenge: "challenge", ExpiresIn: 30, Factors: []string{"totp"}}, nil
}

func (f *fakeMFAActionClient) Verify(_ context.Context, binding application.MFAActionBinding, _ application.MFAActionProof) (application.MFAActionGrant, error) {
	f.verifyBinding = binding
	if f.onVerify != nil {
		f.onVerify()
	}
	return f.grant, nil
}

func (f *fakeMFAActionClient) Consume(_ context.Context, binding application.MFAActionBinding, grant string) error {
	f.consumeBinding, f.consumedGrant = binding, grant
	return nil
}
