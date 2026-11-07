package main

import (
	"errors"
	"io"
	"strings"

	sharedcommand "github.com/openbastion/openbastion/pkg/command"
	"github.com/spf13/cobra"
)

const usage = `usage:
  openbastion-cli user create -authn URL -username NAME -roles ROLE[,ROLE…] [-display NAME] < password
  openbastion-cli audit verify-chain -audit URL
  openbastion-cli mfa enrollment-code -authn URL (-local NAME | -directory NAME [-directory-id ID])
  openbastion-cli mfa reset -authn URL -username NAME
  openbastion-cli mfa keys -authn URL -username NAME
  openbastion-cli mfa revoke-key -authn URL -username NAME -key ID
  openbastion-cli version [--short]`

func newRootCommand(stdin io.Reader) *cobra.Command {
	root := &cobra.Command{
		Use:           "openbastion-cli",
		Short:         "Administration initiale et opérations privilégiées OpenBastion",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE:          func(*cobra.Command, []string) error { return errors.New(usage) },
	}
	root.SetIn(stdin)

	user := &cobra.Command{Use: "user", Short: "Gestion des utilisateurs", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return errors.New(usage) }}
	create := &cobra.Command{
		Use: "create", Short: "Créer le premier utilisateur ou un utilisateur local", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authn, _ := cmd.Flags().GetString("authn")
			username, _ := cmd.Flags().GetString("username")
			display, _ := cmd.Flags().GetString("display")
			roles, _ := cmd.Flags().GetString("roles")
			return userCreate(authn, username, display, roles, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	create.Flags().String("authn", "", "URL of the Authentication Service, e.g. https://authentication:8086")
	create.Flags().String("username", "", "the new user's name")
	create.Flags().String("display", "", "display name (defaults to the username)")
	create.Flags().String("roles", "", "comma-separated roles")
	user.AddCommand(create)

	audit := &cobra.Command{Use: "audit", Short: "Vérification de l'audit", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return errors.New(usage) }}
	verify := &cobra.Command{
		Use: "verify-chain", Short: "Vérifier la chaîne d'audit", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url, _ := cmd.Flags().GetString("audit")
			return verifyChain(url, cmd.OutOrStdout())
		},
	}
	verify.Flags().String("audit", "", "URL of the Audit Service, e.g. https://audit-service:8082")
	audit.AddCommand(verify)

	mfa := &cobra.Command{Use: "mfa", Short: "Gestion des facteurs d'authentification", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return errors.New(usage) }}
	enrollment := &cobra.Command{
		Use: "enrollment-code", Short: "Émettre un code d'enrôlement MFA à usage unique", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authn, _ := cmd.Flags().GetString("authn")
			local, _ := cmd.Flags().GetString("local")
			directory, _ := cmd.Flags().GetString("directory")
			directoryID, _ := cmd.Flags().GetString("directory-id")
			return mfaEnrollmentCode(authn, local, directory, directoryID, cmd.OutOrStdout())
		},
	}
	enrollment.Flags().String("authn", "", "URL of the Authentication Service, e.g. https://authentication:8086")
	enrollment.Flags().String("local", "", "the local account's name")
	enrollment.Flags().String("directory", "", "the directory login name (sAMAccountName or uid)")
	enrollment.Flags().String("directory-id", "", "the directory's id in IDENTITY_PROVIDERS_FILE (ADR-0076); empty: the directory of the LDAP_* variables")

	reset := &cobra.Command{
		Use: "reset", Short: "Réinitialiser le second facteur d'un compte", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authn, _ := cmd.Flags().GetString("authn")
			username, _ := cmd.Flags().GetString("username")
			return mfaReset(authn, username, cmd.OutOrStdout())
		},
	}
	addMFAAccountFlags(reset)

	keys := &cobra.Command{
		Use: "keys", Short: "Lister les clés de sécurité d'un compte", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authn, _ := cmd.Flags().GetString("authn")
			username, _ := cmd.Flags().GetString("username")
			return mfaKeys(authn, username, cmd.OutOrStdout())
		},
	}
	addMFAAccountFlags(keys)

	revoke := &cobra.Command{
		Use: "revoke-key", Short: "Révoquer une clé de sécurité", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authn, _ := cmd.Flags().GetString("authn")
			username, _ := cmd.Flags().GetString("username")
			key, _ := cmd.Flags().GetString("key")
			return mfaRevokeKey(authn, username, key, cmd.OutOrStdout())
		},
	}
	addMFAAccountFlags(revoke)
	revoke.Flags().String("key", "", "the key's identifier, as mfa keys gives it")

	mfa.AddCommand(enrollment, reset, keys, revoke)
	root.AddCommand(user, audit, mfa, sharedcommand.NewVersionCommand())
	return root
}

func addMFAAccountFlags(cmd *cobra.Command) {
	cmd.Flags().String("authn", "", "URL of the Authentication Service, e.g. https://authentication:8086")
	cmd.Flags().String("username", "", "the account's name (ldap:<id> for a directory account)")
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	root := newRootCommand(stdin)
	root.SetArgs(normalizeLegacyLongFlags(args))
	root.SetOut(stdout)
	err := root.Execute()
	if err != nil && strings.Contains(err.Error(), `unknown command`) {
		return errors.New(usage)
	}
	return err
}

// normalizeLegacyLongFlags keeps the CLI's historical single-dash long options
// while Cobra owns parsing and validation of the resulting command tree.
func normalizeLegacyLongFlags(args []string) []string {
	normalized := make([]string, len(args))
	for i, arg := range args {
		if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			normalized[i] = "-" + arg
			continue
		}
		normalized[i] = arg
	}
	return normalized
}
