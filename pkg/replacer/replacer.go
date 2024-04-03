package replacer

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"

	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/pterm/pterm"
)

var HostInfo_originals, HostInfo_Replacements []string
var CommandMap map[string]bool
var HEC_token string
var HEC_url string

func CommandsReplacements(command string) ([]string, []string) {
	var commands []string
	var replacements []string

	line := strings.TrimSpace(command)
	parts := strings.Fields(line)
	commands = append(commands, parts...)

	gibberish := GenerateHashGibberish(parts)
	replacements = append(replacements, strings.Split(gibberish, " ")...)

	return replacements, commands
}

// Return not catched commands:
func GetFalseCommands() []string {
	falseCommands := []string{}
	for cmd, executed := range CommandMap {
		if !executed {
			falseCommands = append(falseCommands, cmd)
		}
	}
	return falseCommands
}

func GenerateHashGibberish(parts []string) string {
	gibberish := ""
	for i, part := range parts {
		if i > 0 {
			gibberish += " " // Add space between parts
		}
		gibberish += generateTruncatedSHA512(part)
	}
	return gibberish
}

func generateTruncatedSHA512(input string) string {
	hasher := sha512.New()
	hasher.Write([]byte(input))
	hash := hex.EncodeToString(hasher.Sum(nil))
	// Truncate the hash to match the length of the original input
	return hash[:len(input)]
}

func UpdateReplacements() {
	HostInfo_originals, HostInfo_Replacements, HEC_token, HEC_url = initialize.ProcessHostFile()
}

func UpdateMachineId() {
	// Read the current machine ID (old one)
	oldMachineID := initialize.ReadMachineID()

	// Generate a new machine ID
	newMachineID := initialize.GenerateNewMachineID()

	// Append the new machine ID to the replacements
	HostInfo_originals = append(HostInfo_originals, oldMachineID)
	HostInfo_Replacements = append(HostInfo_Replacements, newMachineID)

	// Print the information using pterm
	pterm.DefaultSection.WithLevel(2).Println("Machine ID Update")
	pterm.Info.Println("A new machine ID has been generated.")
	pterm.Info.Printfln("New Machine ID: %s", pterm.FgGreen.Sprint(newMachineID))
	pterm.Info.Printfln("The new machine ID will be used for the hostname: %s", pterm.FgCyan.Sprint(HostInfo_Replacements[0])) // Replace 'newMachineID' with 'newHostname' if you have a hostname value
}
