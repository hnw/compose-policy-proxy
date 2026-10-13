// Package compose loads the Compose project that is the policy authority, using
// compose-go's discovery rules and no override, so the proxy resolves the client's project.
package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
)

const Separator = "_"

func Load(ctx context.Context, workingDir string) (*types.Project, error) {
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve working directory: %w", err)
		}
		workingDir = wd
	}
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		return nil, fmt.Errorf("resolve working directory %q: %w", workingDir, err)
	}

	options, err := cli.NewProjectOptions(nil,
		cli.WithWorkingDirectory(abs),
		cli.WithOsEnv,
		cli.WithDotEnv,
		cli.WithConfigFileEnv,
		cli.WithDefaultConfigPath,
	)
	if err != nil {
		return nil, fmt.Errorf("build project options: %w", err)
	}

	project, err := options.LoadProject(ctx)
	if err != nil {
		return nil, fmt.Errorf("load compose project from %q: %w", abs, err)
	}
	project.WorkingDir = abs
	return project, nil
}
