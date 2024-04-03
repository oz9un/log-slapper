package initialize

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pterm/pterm"
	"gopkg.in/yaml.v2"
)

type HostFileConfig struct {
	SplunkIP string            `yaml:"splunk-url"`
	Token    string            `yaml:"token"`
	Host     map[string]string `yaml:"host"`
	IP       map[string]string `yaml:"ip"`
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

// Checks for host.file and creates it if not found
func ChecknCreateHostFile() {
	if _, err := os.Stat("host.file"); os.IsNotExist(err) {

		targetIP, _ := pterm.DefaultInteractiveTextInput.Show("Enter target IP to mimic")
		targetIP = strings.TrimSpace(targetIP)

		targetHostname, _ := pterm.DefaultInteractiveTextInput.Show("Enter target hostname to mimic")
		targetHostname = strings.TrimSpace(targetHostname)

		hecToken, _ := pterm.DefaultInteractiveTextInput.Show("Enter HEC token (leave blank if HEC is not enabled)")
		hecToken = strings.TrimSpace(hecToken)

		hostname, err := os.Hostname()
		if err != nil {
			pterm.Error.Println("Error getting hostname:", err)
			return
		}

		content := fmt.Sprintf("splunk-url: %s\ntoken: %s\nhost: {\n    %s: %s\n}\nip: {\n    %s: %s\n}", dest_ip, hecToken, hostname, targetHostname, local_ip, targetIP)
		err = os.WriteFile("host.file", []byte(content), 0644)
		if err != nil {
			pterm.Error.Println("Error writing to host.file:", err)
			return
		}

		pterm.Success.Println("host.file created successfully.")
		fmt.Println()
	} else {
		pterm.Info.MessageStyle = pterm.NewStyle(pterm.FgYellow)
		pterm.Info.Println("host.file already exists.")
		fmt.Println()
	}
}

func ProcessHostFile() ([]string, []string, string, string) {
	var config HostFileConfig

	// Read YAML file
	yamlFile, err := ioutil.ReadFile("host.file")
	if err != nil {
		return nil, nil, "", ""
	}

	// Unmarshal YAML into Config struct
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, nil, "", ""
	}

	// Extract keys and values
	var keys []string
	var values []string
	for key, value := range config.Host {
		keys = append(keys, key)
		values = append(values, value)
	}
	for key, value := range config.IP {
		keys = append(keys, key)
		values = append(values, value)
	}

	HEC_url = "https://" + config.SplunkIP + ":8088/services/collector"

	return keys, values, config.Token, HEC_url
}

func SetNewConfig() {
	pterm.Println() // Print a blank line for aesthetics

	_, prev_values, prev_token, _ := ProcessHostFile()

	// Get new hostname value from user
	newHostnamePrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue(prev_values[0])
	newHostnameValue, _ := newHostnamePrompt.Show("Enter new hostname value")
	newHostnameValue = strings.TrimSpace(newHostnameValue)

	// Get new IP value from user
	newIPPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue(prev_values[1])
	newIPValue, _ := newIPPrompt.Show("Enter new IP value")
	newIPValue = strings.TrimSpace(newIPValue)

	// Get new HEC token from user
	hecTokenPrompt := pterm.DefaultInteractiveTextInput.WithDefaultValue(prev_token)
	newHecToken, _ := hecTokenPrompt.Show("Enter new HEC token")
	newHecToken = strings.TrimSpace(newHecToken)

	content, err := os.ReadFile("host.file")
	if err != nil {
		pterm.Error.Println("Error reading host.file:", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	inHostSection, inIPSection := false, false
	for i, line := range lines {
		if strings.Contains(line, "token: ") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				// Update token value
				lines[i] = fmt.Sprintf("token: %s", newHecToken)
			}
		} else if strings.Contains(line, "host: {") {
			inHostSection = true
		} else if strings.Contains(line, "ip: {") {
			inHostSection = false
			inIPSection = true
		} else if inHostSection && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				// Update hostname value
				lines[i] = fmt.Sprintf("    %s: %s", strings.TrimSpace(parts[0]), newHostnameValue)
			}
			inHostSection = false // Assuming only one entry under host: { ... }
		} else if inIPSection && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				// Update IP value
				lines[i] = fmt.Sprintf("    %s: %s", strings.TrimSpace(parts[0]), newIPValue)
			}
			inIPSection = false // Assuming only one entry under ip: { ... }
		}
	}

	updatedContent := strings.Join(lines, "\n")
	if err := os.WriteFile("host.file", []byte(updatedContent), 0644); err != nil {
		pterm.Error.Println("Error writing updated configuration to host.file:", err)
		return
	}

	pterm.Success.Println("host.file updated successfully.")
	fmt.Println()
}

func ViewCurrentConfig() {
	file, err := os.Open("host.file")
	if err != nil {
		pterm.Error.Println("Error opening host.file:", err)
		return
	}
	defer file.Close()

	var data [][]string

	scanner := bufio.NewScanner(file)
	pterm.DefaultSection.Println("Current Configuration")

	for scanner.Scan() {
		line := scanner.Text()

		// Directly print interface line
		if strings.HasPrefix(line, "interface:") {
			data = append(data, []string{"interface", strings.TrimSpace(strings.TrimPrefix(line, "interface:"))})
			continue
		}

		// For host and ip lines, extract and print formatted information
		if strings.Contains(line, "{") || strings.Contains(line, "}") {
			// This line indicates the start or end of a block, so we skip printing
			continue
		} else if strings.Contains(line, ":") {
			// Assuming the line contains a key-value pair separated by ':'
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				data = append(data, []string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		pterm.Error.Println("Error reading host.file:", err)
	}

	// Render the table using pterm
	if len(data) > 0 {
		pterm.DefaultTable.WithHasHeader(false).WithData(data).Render()
	} else {
		pterm.Info.Println("No configuration to display.")
	}
}
