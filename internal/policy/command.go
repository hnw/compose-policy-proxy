package policy

import (
	"fmt"
	"slices"
	"strings"
)

// The Compose commands this proxy supports, named as the CLI accepts them.
const (
	commandRun     = "run"
	commandUp      = "up"
	commandDown    = "down"
	commandStart   = "start"
	commandStop    = "stop"
	commandRestart = "restart"
	commandPull    = "pull"
	commandLogs    = "logs"
	commandExec    = "exec"
)

// supportedCommands is every command the policy knows how to authorize, and is also the
// default, so a command added here is allowed unless an operator narrows the set.
var supportedCommands = []string{
	commandRun, commandUp, commandDown, commandStart, commandStop, commandRestart,
	commandPull, commandLogs, commandExec,
}

// Commands is the set of Compose commands a client may perform, as configured by
// --allow-command. It is a startup-time setting like the Compose project, so changing
// it means restarting the proxy. It selects what is authorized; it does not
// authenticate the client that asks.
type Commands []string

// DefaultCommandList is the command list used when --allow-command is not given.
var DefaultCommandList = strings.Join(supportedCommands, ",")

// DefaultCommands is every supported command, which is what --allow-command grants by
// omission. It returns a copy, so a caller cannot widen the default by appending to it.
func DefaultCommands() Commands {
	return slices.Clone(supportedCommands)
}

// ParseCommands reads the comma-separated command list. An empty list authorizes no
// command at all, and an unsupported name is refused rather than kept as a name no
// operation answers to.
func ParseCommands(list string) (Commands, error) {
	var commands Commands
	for field := range strings.SplitSeq(list, ",") {
		name := strings.TrimSpace(field)
		if name == "" {
			continue
		}
		if !slices.Contains(supportedCommands, name) {
			return nil, fmt.Errorf("--allow-command: %q is not supported; choose from %s",
				name, DefaultCommandList)
		}
		if slices.Contains(commands, name) {
			continue
		}
		commands = append(commands, name)
	}
	slices.Sort(commands)
	return commands, nil
}

func (c Commands) check(command string) error {
	if slices.Contains(c, command) {
		return nil
	}
	return denyf("", "", "docker compose %s is not available through this proxy", command)
}

// checkAny authorizes an operation that any one of the named commands performs. The
// refusal names the first of them, which is the command a client would be asking for.
func (c Commands) checkAny(commands ...string) error {
	for _, command := range commands {
		if slices.Contains(c, command) {
			return nil
		}
	}
	return c.check(commands[0])
}

var createOperations = map[string]bool{
	"/networks/create": true,
	"/volumes/create":  true,
}

var serviceContainerOperations = map[string][]string{
	"/containers/{id}/start":   {commandStart, commandUp},
	"/containers/{id}/stop":    {commandStop, commandUp, commandDown},
	"/containers/{id}/restart": {commandRestart},
	"/containers/{id}":         {commandDown, commandUp},
}

func (c Commands) checkRunOrUp() error {
	if slices.Contains(c, commandRun) || slices.Contains(c, commandUp) {
		return nil
	}
	return denyf("", "", "docker compose %s and docker compose %s are both unavailable through this proxy",
		commandRun, commandUp)
}
