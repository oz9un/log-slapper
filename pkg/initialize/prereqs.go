package initialize

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/pterm/pterm"
)

type SettingsFileConfig struct {
	TargetIndexerIP string `json:"ip_info"`
	TokenInfo       string `json:"token_info"`
}

// checkIfSudo checks if the program is executed with superuser privileges.
// It warns the user to run the program as sudo if not already.
func CheckIfSudo() {
	// Get the effective user ID.
	euid := os.Geteuid()

	// Check if the effective user ID is not 0 (which is the user ID of the root).
	if euid != 0 {
		pterm.Error.Println("Warning: This program needs to be run as root (sudo). Please rerun it using sudo.")
		os.Exit(1)
	}
}

func SudoCheck() int {
	// Get the effective user ID.
	euid := os.Geteuid()

	return euid
}

// ReadMachineID reads the machine ID from /etc/machine-id.
func ReadMachineID() string {
	data, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// GenerateNewMachineID generates a new machine ID in the format of 32 hexadecimal characters.
func GenerateNewMachineID() string {
	const idLength = 16 // 16 bytes = 128 bits
	buffer := make([]byte, idLength)
	_, err := io.ReadFull(rand.Reader, buffer)
	if err != nil {
		return ""
	}

	// Convert to hexadecimal format
	return fmt.Sprintf("%x", buffer)
}

// Checks for log.settings and creates it if not found
func ChecknCreateSettingsFile(indexerip_manual bool) {
	if _, err := os.Stat("log.settings"); os.IsNotExist(err) {

		if indexerip_manual {

			targetIndexerIP, _ := pterm.DefaultInteractiveTextInput.Show("Enter target Indexer/HF IP")
			targetIndexerIP = strings.TrimSpace(targetIndexerIP)

			/* v2
			localIP, _ := pterm.DefaultInteractiveTextInput.Show("Enter your local IP")
			localIP = strings.TrimSpace(localIP)
			*/

			HEC_url = "https://" + targetIndexerIP + ":8088/services/collector"
			dest_ip = targetIndexerIP
			//local_ip = localIP
		}

		/* v2
		targetIP, _ := pterm.DefaultInteractiveTextInput.Show("Enter target IP to mimic")
		targetIP = strings.TrimSpace(targetIP)

		targetHostname, _ := pterm.DefaultInteractiveTextInput.Show("Enter target hostname to mimic")
		targetHostname = strings.TrimSpace(targetHostname)
		*/

		hecToken, _ := pterm.DefaultInteractiveTextInput.Show("Enter HEC token (leave blank if HEC is not enabled)")
		hecToken = strings.TrimSpace(hecToken)

		/* v2
		hostname, err := os.Hostname()
		if err != nil {
			pterm.Error.Println("Error getting hostname:", err)
			return
		}

		content := fmt.Sprintf("splunk-url: %s\ntoken: %s\nhost: {\n    %s: %s\n}\nip: {\n    %s: %s\n}", dest_ip, hecToken, hostname, targetHostname, local_ip, targetIP)
		*/

		data := SettingsFileConfig{
			TargetIndexerIP: dest_ip,
			TokenInfo:       hecToken,
		}

		// Marshal the data into JSON bytes
		jsonData, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			fmt.Printf("error marshaling JSON: %w", err)
		}

		// Define the file name
		fileName := "log.settings"

		// Create a new file or truncate existing file
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Printf("error creating file: %w", err)
		}
		defer file.Close()

		// Write JSON data to file
		_, err = file.Write(jsonData)
		if err != nil {
			fmt.Printf("error writing to file: %w", err)
		}

		pterm.Success.Printf("File created successfully: %s\n", fileName)
		fmt.Println()
	} else {
		pterm.Info.MessageStyle = pterm.NewStyle(pterm.FgYellow)
		pterm.Info.Println("log.settings already exists.")
		fmt.Println()
	}
}

// getDefaultIP returns the first non-loopback IPv4 address it finds.
func getDefaultIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		pterm.Error.Println("Failed to get network interfaces:", err)
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			// Skip loopback interfaces to avoid getting 127.0.0.1
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			pterm.Error.Println("Error getting addresses:", err)
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip := v.IP.To4() // Convert potential IPv4 address to 4-byte representation
				if ip != nil && !ip.IsLoopback() {
					return ip.String() // Return the first non-loopback IPv4 address
				}
			}
		}
	}
	return "" // Return an empty string if no suitable address is found
}

// GetHostAndIPDetails prompts the user for hostnames and IPs, with default values.
func GetHostAndIPDetails() ([]string, []string) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil
	}
	currentIP := getDefaultIP()
	if currentIP == "" {
		return nil, nil
	}

	defaultCurrentHostname := hostname
	defaultTargetHostname := "target-hostname"
	defaultCurrentIP := currentIP
	defaultTargetIP := "10.10.10.10"

	currentHostname, _ := pterm.DefaultInteractiveTextInput.WithTextStyle(pterm.FgLightRed.ToStyle()).WithDefaultValue(defaultCurrentHostname).Show("→ " + "Enter current hostname")
	targetHostname, _ := pterm.DefaultInteractiveTextInput.WithTextStyle(pterm.FgLightRed.ToStyle()).WithDefaultValue(defaultTargetHostname).Show("→ " + "Enter target hostname to mimic")
	currIP, _ := pterm.DefaultInteractiveTextInput.WithTextStyle(pterm.FgLightRed.ToStyle()).WithDefaultValue(defaultCurrentIP).Show("→ " + "Enter current IP")
	targetIP, _ := pterm.DefaultInteractiveTextInput.WithTextStyle(pterm.FgLightRed.ToStyle()).WithDefaultValue(defaultTargetIP).Show("→ " + "Enter target IP to mimic")

	originals := []string{currentHostname, currIP}
	replacements := []string{targetHostname, targetIP}

	return originals, replacements
}

func ProcessSettingsFile() (string, string) {
	file, err := os.Open("log.settings")
	if err != nil {
		pterm.Error.Println("Error opening log.settings:", err)
		return "", ""
	}
	defer file.Close()

	// Decode the JSON data
	var config SettingsFileConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		pterm.Error.Println("Error decoding config.json:", err)
		return "", ""
	}

	//pterm.DefaultSection.Println("Current Configuration")

	return config.TokenInfo, config.TargetIndexerIP
}

func SetNewConfig() {
	pterm.Println() // Print a blank line for aesthetics

	//prev_token, hec_url := ProcessSettingsFile()

	file, err := os.Open("log.settings")
	if err != nil {
		fmt.Printf("error opening log.settings: %w", err)
	}

	// Decode the existing JSON data
	var config SettingsFileConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		file.Close() // Close the file explicitly on error
		fmt.Printf("error decoding log.settings: %w", err)
	}
	file.Close() // Close the file after reading

	// Ask user for new values, using existing values as defaults
	pterm.DefaultSection.Println("Update Configuration")
	newIPInfo, _ := pterm.DefaultInteractiveTextInput.WithDefaultValue(config.TargetIndexerIP).Show("Enter new Indexer/HF IP")
	newTokenInfo, _ := pterm.DefaultInteractiveTextInput.WithDefaultValue(config.TokenInfo).Show("Enter new HEC token")

	// Update the config struct with new values
	config.TargetIndexerIP = newIPInfo
	config.TokenInfo = newTokenInfo

	// Open the file again for writing
	file, err = os.Create("log.settings")
	if err != nil {
		fmt.Printf("error creating log.settings: %w", err)
	}
	defer file.Close()

	// Marshal the updated data into JSON bytes
	updatedJsonData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		fmt.Printf("error marshaling JSON: %w", err)
	}

	// Write updated JSON data to file
	if _, err = file.Write(updatedJsonData); err != nil {
		fmt.Printf("error writing to log.settings: %w", err)
	}

	pterm.Success.Println("Configuration updated successfully.")
	fmt.Println()
}

func ViewCurrentConfig() {
	file, err := os.Open("log.settings")
	if err != nil {
		pterm.Error.Println("Error opening log.settings:", err)
		return
	}
	defer file.Close()

	// Decode the JSON data
	var config SettingsFileConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		pterm.Error.Println("Error decoding config.json:", err)
		return
	}

	pterm.DefaultSection.Println("Current Configuration")

	// Check if values are empty and assign "(none)" if they are
	ipInfo := config.TargetIndexerIP
	if ipInfo == "" {
		ipInfo = "(none)"
	}
	tokenInfo := config.TokenInfo
	if tokenInfo == "" {
		tokenInfo = "(none)"
	}

	// Prepare data for displaying in a table
	data := [][]string{
		{"Indexer/HF IP", ipInfo},
		{"HEC Token", tokenInfo},
	}

	// Render the table using pterm
	pterm.DefaultTable.WithHasHeader(false).WithData(data).WithBoxed().Render()
	fmt.Println()
}
