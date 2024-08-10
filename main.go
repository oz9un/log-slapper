package main

import (
	"os"
	"time"

	"github.com/oz9un/log-slapper/pkg/cmd"
	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

func main() {
	//sudoCheck := initialize.CheckIfSudo()

	pterm.DefaultBigText.WithLetters(
		putils.LettersFromStringWithStyle("log", pterm.FgCyan.ToStyle()),
		putils.LettersFromStringWithStyle("-", pterm.FgBlue.ToStyle()),
		putils.LettersFromStringWithStyle("slapper", pterm.FgLightRed.ToStyle())).
		Render()

	args := os.Args
	if !(len(args) > 1 && (args[1] == "--help" || args[1] == "help" || args[1] == "-h")) {
		if _, err := os.Stat("log.settings"); os.IsNotExist(err) {
			// Print a message about the log.settings not being found
			infoPrefix := pterm.Prefix{Text: "NO SETTINGS FILE", Style: pterm.NewStyle(pterm.BgLightYellow, pterm.FgRed)}
			infoStyle := pterm.NewStyle(pterm.FgYellow)
			pterm.Info.WithPrefix(infoPrefix).WithMessageStyle(infoStyle).Println("\"log.settings\" is not found. Let's create a new one.")

			sudoCheck := initialize.SudoCheck()

			if sudoCheck == 0 {
				pterm.Info.Println("Program started as ROOT. Target Indexer/HF IP will be AUTOMATICALLY detected.")

				// Start a spinner and set a message
				spinnerSuccess, _ := pterm.DefaultSpinner.Start("To detect the target Splunk instance and local IP, a scan is starting...")
				time.Sleep(3 * time.Second)

				// Assuming the scan is done, stop the spinner and show the result
				spinnerSuccess.Success()

				initialize.Detect()
				initialize.ChecknCreateSettingsFile(false)
			} else {
				pterm.Warning.Println("Program started as normal user. Target Indexer/HF IP and LOCAL IP should be MANUALLY entered.")
				initialize.ChecknCreateSettingsFile(true)
			}
		}

		//initialize.ProcessSettingsFile()
	}
	cmd.Execute()
}
