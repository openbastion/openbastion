// Package command contains Cobra commands shared by OpenBastion production executables.
package command

import (
	"context"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/spf13/cobra"
)

// NewVersionCommand creates the common, side-effect-free version command.
func NewVersionCommand() *cobra.Command {
	return newVersionCommand(buildinfo.Current)
}

func newVersionCommand(current func() buildinfo.Info) *cobra.Command {
	var short bool
	cmd := &cobra.Command{
		Use:           "version",
		Short:         "Affiche les informations de version et de build",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := current()
			if short {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), info.Short())
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), info.String())
			return err
		},
	}
	cmd.Flags().BoolVar(&short, "short", false, "Affiche uniquement la version")
	return cmd
}

// NewServiceCommand creates the root command for a service executable. Running
// the binary without arguments preserves the service's existing startup path;
// the version subcommand exits before that path can initialize any dependency.
func NewServiceCommand(name string, run func()) *cobra.Command {
	root := &cobra.Command{
		Use:           name,
		Short:         "Démarre le service " + name,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Run: func(*cobra.Command, []string) {
			run()
		},
	}
	root.AddCommand(NewVersionCommand())
	return root
}

// Probe asks a running service whether it is up, on port and path: nil for yes.
type Probe func(ctx context.Context, port int, path string) error

// NewProbeCommand is the healthcheck of an image with no shell (ADR-0072): `<service> probe --port
// N --path /readyz` exits 0 when the service answers 200, 1 otherwise, within --timeout. It starts
// nothing of the service.
func NewProbeCommand(probe Probe) *cobra.Command {
	var port int
	var path string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "probe",
		Short:         "Vérifie que le service en cours d'exécution répond (healthcheck)",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if port == 0 {
				return fmt.Errorf("probe: --port is required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			return probe(ctx, port, path)
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "Port HTTP du service, sur 127.0.0.1")
	cmd.Flags().StringVar(&path, "path", "/healthz", "Chemin interrogé")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Second, "Délai de la réponse")
	return cmd
}
