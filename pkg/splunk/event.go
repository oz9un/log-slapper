package splunk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/pterm/pterm"
)

// LoginEvent represents the structure of a login event sent to Splunk.
type SplunkEvent struct {
	Event      string                 `json:"event"`
	Sourcetype string                 `json:"sourcetype"`
	Source     string                 `json:"source"`
	Index      string                 `json:"index"`
	Host       string                 `json:"host"`
	Time       int64                  `json:"time"` // Unix timestamp field
	Fields     map[string]interface{} `json:"fields"`
}

func FormatWithRandomSeconds(t time.Time) (string, time.Time) {
	// Generate a random number of seconds (0 to 59).
	randomSeconds := time.Duration(rand.Intn(60)) * time.Second

	// Add the random seconds to the provided time.
	updatedTime := t.Add(randomSeconds)

	// Format the time with the random seconds to a string.
	formattedTime := updatedTime.Format("01/02/2006 15:04:05")

	// Determine AM/PM part based on the hour
	ampm := "AM"
	if updatedTime.Hour() >= 12 {
		ampm = "PM"
	}

	// Append AM/PM part to the formatted string
	formattedTimeWithAmPm := fmt.Sprintf("%s %s", formattedTime, ampm)

	return formattedTimeWithAmPm, updatedTime
}

func GenerateLoginEvent(domain, subnet string, eventTime time.Time, targetAcc string) (SplunkEvent, string, string) {
	// Generate random computer and account names within the specified domain
	hostName := fmt.Sprintf("PC-%03d", rand.Intn(255))
	computerName := fmt.Sprintf("%s.%s", hostName, domain)

	// Format the event timestamp for the beginning of the event string
	eventTimeString := eventTime.Format("01/02/2006 03:04:05 PM")

	// Construct the event message
	event := fmt.Sprintf("%s\nLogName=Security\nEventCode=4624\nEventType=0\nComputerName=%s\nSourceName=Microsoft Windows security auditing.\nType=Information\nRecordNumber=%d\nKeywords=Audit Success\nTaskCategory=Logon\nOpCode=Info\nMessage=An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\t%s\n\tAccount Domain:\t\t%s\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t9\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nImpersonation Level:\t\tImpersonation\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Domain:\t\t%s\n\tLogon ID:\t\t0x276B08\n\tLinked Logon ID:\t\t0x0\n\tNetwork Account Name:\t%s\n\tNetwork Account Domain:\t%s\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\n\nProcess Information:\n\tProcess ID:\t\t0x17c\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t::1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tseclogo\n\tAuthentication Package:\tNegotiate\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0", eventTimeString, computerName, rand.Intn(10000)+1000, targetAcc, domain, domain, targetAcc, domain)

	ip, _ := randomIpFromCIDR(subnet)

	eventFields := map[string]interface{}{
		"host_ip":   ip,
		"host_name": hostName,
	}

	// Convert the event timestamp to Unix time for the "time" field
	unixTime := eventTime.Unix()

	return SplunkEvent{
		Event:      event,
		Sourcetype: "WinEventLog",
		Source:     "WinEventLog:Security",
		Index:      "winevent",
		Host:       computerName,
		Time:       unixTime,
		Fields:     eventFields,
	}, hostName, ip.String()
}

func GenerateProcessCreationEvent(domain, targetIp string, targetHostname string, eventTime time.Time, accountName, newProcessName string, parameters string) SplunkEvent {
	computerName := fmt.Sprintf("%s.%s", targetHostname, domain)

	eventTimeString := eventTime.Format("01/02/2006 15:04:05")

	event := fmt.Sprintf("%s\nLogName=Security\nSourceName=Microsoft Windows security auditing.\nEventCode=4688\nEventType=0\nType=Information\nComputerName=%s\nTaskCategory=Process Creation\nOpCode=Info\nRecordNumber=%d\nKeywords=Audit Success\nMessage=A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\t-\n\tAccount Name:\t\t%s\n\tAccount Domain:\t\t%s\n\tLogon ID:\t\t0x9BB5354DA\n\nTarget Subject:\n\tSecurity ID:\n\tAccount Name:\n\tAccount Domain:\n\tLogon ID:\n\nProcess Information:\n\tNew Process ID:\t\t0x1e4\n\tNew Process Name:\t%s\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\tMandatory Label\\High Mandatory Level\n\tCreator Process ID:\t0x11f0\n\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tProcess Command Line:\t%s", eventTimeString, computerName, rand.Intn(10000)+1000, accountName, domain, newProcessName, newProcessName+" "+parameters)

	eventFields := map[string]interface{}{
		"host_ip":   targetIp,
		"host_name": targetHostname,
	}

	unixTime := eventTime.Unix()

	return SplunkEvent{
		Event:      event,
		Sourcetype: "WinEventLog",
		Source:     "WinEventLog:Security",
		Index:      "winevent",
		Host:       computerName,
		Time:       unixTime,
		Fields:     eventFields,
	}
}

// Function to generate the audit message part
func generateAuditMsg(eventTime time.Time) string {
	// Increment and retrieve the next event identifier
	eventID := rand.Int63n(10000000) // Generates a random number up to 10 million
	// Use the provided eventTime for the timestamp
	timestamp := eventTime.Unix()
	milliseconds := eventTime.Nanosecond() / 1000000

	// Format the audit message
	return fmt.Sprintf("msg=audit(%d.%03d:%d)", timestamp, milliseconds, eventID)
}

func GenerateExecveEventFromCommand(eventTime time.Time, commandLine string, targetIp string, targetHostname string) SplunkEvent {
	// Split the command line into command and arguments
	parts := strings.Fields(commandLine)

	// Convert the event timestamp to Unix format
	unixTime := eventTime.Unix()
	// Construct the audit message part using eventTime
	auditMsg := generateAuditMsg(eventTime)

	// Initialize the event message with the timestamp and argument count (argc)
	event := fmt.Sprintf("type=EXECVE %s: argc=%d", auditMsg, len(parts))

	// Iterate over the command and arguments to append them to the event message
	for i, part := range parts {
		event += fmt.Sprintf(" a%d=\"%s\"", i, part)
	}

	newMachineID := initialize.GenerateNewMachineID()

	eventFields := map[string]interface{}{
		"host_ip":    targetIp,
		"machine_id": newMachineID,
	}

	return SplunkEvent{
		Event:      event,
		Sourcetype: "linux:audit",
		Source:     "/var/log/audit/audit.log",
		Index:      "linux_auditd",
		Host:       targetHostname,
		Time:       unixTime,
		Fields:     eventFields,
	}
}

func GenerateLoginFailedEvent(domain, subnet string, eventTime time.Time, targetAcc string) (SplunkEvent, string, string) {
	// Generate random computer and account names within the specified domain
	hostName := fmt.Sprintf("PC-%03d", rand.Intn(255))
	computerName := fmt.Sprintf("%s.%s", hostName, domain)
	//accountName := fmt.Sprintf("User%d", rand.Intn(1000))

	randomSourceIP, _ := randomIpFromCIDR(subnet)

	// Format the event timestamp for the beginning of the event string
	eventTimeString := eventTime.Format("01/02/2006 03:04:05 PM")

	// Construct the event message
	event := fmt.Sprintf("%s\nLogName=Security\nEventCode=4625\nEventType=0\nComputerName=%s\nSourceName=Microsoft Windows security auditing.\nType=FailureAudit\nRecordNumber=%d\nKeywords=Audit Failure\nTaskCategory=Logon\nOpCode=Info\nMessage=An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Domain:\t\t%s\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t%s\n\tAccount Domain:\t\t%s\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t%s\n\tSource Network Address:\t%s\n\tSource Port:\t\t50085\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp\n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0", eventTimeString, computerName, rand.Intn(10000)+1000, domain, targetAcc, domain, computerName, randomSourceIP)

	ip, _ := randomIpFromCIDR(subnet)

	eventFields := map[string]interface{}{
		"host_ip":   ip,
		"host_name": hostName,
	}

	// Convert the event timestamp to Unix time for the "time" field
	unixTime := eventTime.Unix()

	return SplunkEvent{
		Event:      event,
		Sourcetype: "WinEventLog",
		Source:     "WinEventLog:Security",
		Index:      "winevent",
		Host:       computerName,
		Time:       unixTime,
		Fields:     eventFields,
	}, hostName, ip.String()
}

// SendLoginEvent sends a generated login event to the Splunk HEC endpoint.
func SendHECEvent(hecURL, hecToken string, event SplunkEvent) (err error) {
	if hecToken == "" {
		return fmt.Errorf("NO HEC TOKEN PROVIDED")
	}
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("JSON Marshall error")
	}

	req, err := http.NewRequest("POST", hecURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Set("Authorization", "Splunk "+hecToken)
	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		pterm.Error.Printf("HTTP Error: %d - %s", resp.StatusCode, resp.Status)
		return fmt.Errorf("HTTP Error: %d - %s", resp.StatusCode, resp.Status)
	}

	return nil
}

// sendDataToSplunk sends the formatted data to the Splunk server.
func SendRawData(helloData, customFieldsData []byte, targetIndexer string) error {
	conn, err := net.Dial("tcp", targetIndexer)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(helloData); err != nil {
		return err
	}

	response := make([]byte, 1024)
	if _, err := conn.Read(response); err != nil {
		return err
	}

	if _, err := conn.Write(customFieldsData); err != nil {
		return err
	}

	return nil
}
