// Package command contains Cobra commands shared by OpenBastion production executables.
package command

import (
	"fmt"

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
