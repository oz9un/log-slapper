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
	initialize.CheckIfSudo()

	pterm.DefaultBigText.WithLetters(
		putils.LettersFromStringWithStyle("log", pterm.FgCyan.ToStyle()),
		putils.LettersFromStringWithStyle("-", pterm.FgBlue.ToStyle()),
		putils.LettersFromStringWithStyle("slapper", pterm.FgLightRed.ToStyle())).
		Render()

	args := os.Args
	if !(len(args) > 1 && (args[1] == "--help" || args[1] == "help" || args[1] == "-h")) {
		if _, err := os.Stat("host.file"); os.IsNotExist(err) {
			// Print a message about the host.file not being found
			pterm.Info.Prefix = pterm.Prefix{Text: "NO HOST FILE", Style: pterm.NewStyle(pterm.BgLightYellow, pterm.FgRed)}
			pterm.Info.MessageStyle = pterm.NewStyle(pterm.FgYellow)
			pterm.Info.Println("\"host.file\" is not found. Let's create a new one.")

			// Start a spinner and set a message
			spinnerSuccess, _ := pterm.DefaultSpinner.Start("To detect the target Splunk instance and local IP, a scan is starting...")
			time.Sleep(3 * time.Second)

			// Assuming the scan is done, stop the spinner and show the result
			spinnerSuccess.Success()
			initialize.Detect()
			initialize.ChecknCreateHostFile()
		}

		initialize.ProcessHostFile()
	}
	cmd.Execute()
}
