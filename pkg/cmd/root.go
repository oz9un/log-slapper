package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/oz9un/log-slapper/pkg/attacks"
	"github.com/oz9un/log-slapper/pkg/command"
	"github.com/oz9un/log-slapper/pkg/initialize"
	"github.com/oz9un/log-slapper/pkg/replacer"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// Create a struct to hold flag values
var CFG = struct {
	eventType         string
	count             int
	subnet            string
	startTime         string
	endTime           string
	domain            string
	hec_token         string
	interactive       bool
	verbose           bool
	accountName       string
	command           string
	execTime          string
	processName       string
	processParameters string
	targetIp          string
	hostname          string
}{}

func interactiveMode() {
	log.SetOutput(ioutil.Discard)
	replacer.CommandMap = make(map[string]bool)

	initialize.ChecknCreateHostFile()
	replacer.UpdateReplacements()

	// Options for interactive select
	options := []string{
		"View current configuration",
		"Set new config (hostname/ip)",
		pterm.FgRed.Sprint("Target shell mode (TCP) 👹"),
		pterm.FgMagenta.Sprint("Built-in attacks (HEC) 🗡"),
		"Exit",
	}

	// Options for interactive select
	osOptions := []string{
		pterm.FgLightBlue.Sprint("Windows 🪟"),
		pterm.FgYellow.Sprint("*nix 🐧"),
		pterm.FgGray.Sprint("Back to the main menu"),
	}

	// Options for interactive select
	windowsAttackOptions := []string{
		pterm.LightGreen("Login success") + " event spam",
		pterm.LightRed("Login failed") + " event spam",
		pterm.LightYellow("New process created") + " event creation",
		pterm.FgGray.Sprint("Back to the main menu"),
	}

	// Options for interactive select
	nixAttackOptions := []string{
		pterm.LightRed("EXECVE") + " event creation",
		pterm.FgGray.Sprint("Back to the main menu"),
	}

	// Use PTerm's interactive select feature
	for {
		selectedOption, err := pterm.DefaultInteractiveSelect.WithOptions(options).Show()
		if err != nil {
			pterm.Error.Println("Something went wrong:", err)
			return
		}

		switch {
		case selectedOption == "View current configuration":
			initialize.ViewCurrentConfig()
		case selectedOption == "Set new config (hostname/ip)":
			initialize.SetNewConfig()
			replacer.UpdateReplacements()
		case strings.Contains(selectedOption, "Built-in attacks"):
			selectedOptionOS, err := pterm.DefaultInteractiveSelect.WithOptions(osOptions).Show("Select the target Operating System")
			if err != nil {
				pterm.Error.Println("Something went wrong:", err)
				return
			}
			switch {
			case strings.Contains(selectedOptionOS, "Windows"):
				selectedWindowsAttack, err := pterm.DefaultInteractiveSelect.WithOptions(windowsAttackOptions).Show("Select an available attack type for Windows")
				if err != nil {
					pterm.Error.Println("Something went wrong:", err)
					return
				}
				switch {
				case strings.Contains(selectedWindowsAttack, "failed"):
					targetDomain, targetSubnet, count, targetAcc := attacks.LoginSpamGetInput()
					attacks.LoginFailEventSpam(count, targetDomain, targetSubnet, replacer.HEC_url, replacer.HEC_token, targetAcc)
				case strings.Contains(selectedWindowsAttack, "success"):
					targetDomain, targetSubnet, count, targetAcc := attacks.LoginSpamGetInput()
					attacks.LoginEventSpam(count, targetDomain, targetSubnet, replacer.HEC_url, replacer.HEC_token, targetAcc)
				case strings.Contains(selectedWindowsAttack, "process"):
					targetDomain, targetHostname, targetIp, processName, processParameters, targetAccount := attacks.ProcessCreateGetInput()
					attacks.ProcessCreateEvent(targetDomain, targetHostname, targetIp, processName, processParameters, targetAccount, replacer.HEC_url, replacer.HEC_token)
				case strings.Contains(selectedWindowsAttack, "Back"):
					interactiveMode()
				}
			case strings.Contains(selectedOptionOS, "nix"):
				selectedNixAttack, err := pterm.DefaultInteractiveSelect.WithOptions(nixAttackOptions).Show("Select an available attack type for Nix")
				if err != nil {
					pterm.Error.Println("Something went wrong:", err)
					return
				}
				switch {
				case strings.Contains(selectedNixAttack, "EXECVE"):
					command, targetHostname, targetIp := attacks.ExecveGetInput()
					attacks.ExecveEvent(targetIp, targetHostname, command, replacer.HEC_url, replacer.HEC_token)
				case strings.Contains(selectedNixAttack, "Back"):
					interactiveMode()
				}
			case strings.Contains(selectedOptionOS, "Back"):
				interactiveMode()
			}
		case strings.Contains(selectedOption, "Target shell mode"):
			command.RunCommand()
		case selectedOption == "Exit":
			pterm.Info.Println("Exiting...")
			os.Exit(1)
		default:
			return
		}
	}
}

var winLoginCmd = &cobra.Command{
	Use:   "win_login",
	Short: "Generate fake Windows login events",
	Long:  `This command generates fake Windows login events.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("domain")
		cmd.MarkFlagRequired("token")
		cmd.MarkFlagRequired("subnet")
		cmd.MarkFlagRequired("account")
		cmd.MarkFlagRequired("starttime")
		cmd.MarkFlagRequired("endtime")
	},
	Run: func(cmd *cobra.Command, args []string) {
		attacks.LoginEventParameterCheck(CFG.startTime, CFG.endTime)
		attacks.LoginEventSpam(CFG.count, CFG.domain, CFG.subnet, initialize.HEC_url, CFG.hec_token, CFG.accountName)
	},
}

var winFailCmd = &cobra.Command{
	Use:   "win_fail",
	Short: "Generate fake Windows fail events",
	Long:  `This command generates fake Windows fail events.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("domain")
		cmd.MarkFlagRequired("token")
		cmd.MarkFlagRequired("subnet")
		cmd.MarkFlagRequired("account")
		cmd.MarkFlagRequired("starttime")
		cmd.MarkFlagRequired("endtime")
	},
	Run: func(cmd *cobra.Command, args []string) {
		attacks.LoginEventParameterCheck(CFG.startTime, CFG.endTime)
		attacks.LoginFailEventSpam(CFG.count, CFG.domain, CFG.subnet, initialize.HEC_url, CFG.hec_token, CFG.accountName)
	},
}
var winProcess = &cobra.Command{
	Use:   "win_process",
	Short: "Generate fake commands for target windows",
	Long:  `It mimics normal powershell executions.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("domain")
		cmd.MarkFlagRequired("hostname")
		cmd.MarkFlagRequired("ip")
		cmd.MarkFlagRequired("process")
		cmd.MarkFlagRequired("parameters")
		cmd.MarkFlagRequired("exectime")
		cmd.MarkFlagRequired("account")
		cmd.MarkFlagRequired("token")
	},
	Run: func(cmd *cobra.Command, args []string) {
		attacks.ProcessCreateEventParameterCheck(CFG.execTime)
		attacks.ProcessCreateEvent(CFG.domain, CFG.hostname, CFG.targetIp, CFG.processName, CFG.processParameters, CFG.accountName, initialize.HEC_url, CFG.hec_token)
	},
}
var nixCommand = &cobra.Command{
	Use:   "nix_command",
	Short: "Generate fake commands for target nix",
	Long:  `It mimics normal command line executions.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("hostname")
		cmd.MarkFlagRequired("ip")
		cmd.MarkFlagRequired("command")
		cmd.MarkFlagRequired("exectime")
		cmd.MarkFlagRequired("token")
	},
	Run: func(cmd *cobra.Command, args []string) {
		attacks.ExecveEventParameterCheck(CFG.execTime)
		attacks.ExecveEvent(CFG.targetIp, CFG.hostname, CFG.command, initialize.HEC_url, CFG.hec_token)
	},
}

var interactiveCommand = &cobra.Command{
	Use:   "interactive",
	Short: "Interactive mode",
	Long:  `This command runs log-slapper in an interactive mode.`,
	PreRun: func(cmd *cobra.Command, args []string) {
	},
	Run: func(cmd *cobra.Command, args []string) {
		interactiveMode()
	},
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "log-slapper",
	Short: "A tool to generate fake logs to confuse blue teams.",
	Long:  `log-slapper is a CLI tool to generate fake logs and more.`,
	// This is where your program's logic will start executing.
	Run: func(cmd *cobra.Command, args []string) {
		// Check if the command was called without any subcommands or flags
		if len(args) == 0 {
			// Run the application in interactive mode
			interactiveMode()
			return
		}
	},
}

func completionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "completion",
		Short: "Generate the autocompletion script for the specified shell",
	}
}

func init() {
	// Add flags specific to win_login
	winLoginCmd.Flags().SortFlags = false
	winLoginCmd.Flags().IntVarP(&CFG.count, "count", "c", 10, "Number of events to generate")
	winLoginCmd.Flags().StringVar(&CFG.domain, "domain", "", "Target domain name")
	winLoginCmd.Flags().StringVarP(&CFG.subnet, "subnet", "s", "", "Subnet in which to simulate events")
	winLoginCmd.Flags().StringVarP(&CFG.hec_token, "token", "t", "", "HEC token")
	winLoginCmd.Flags().StringVarP(&CFG.accountName, "account", "a", "", "Target account name")
	winLoginCmd.Flags().StringVar(&CFG.startTime, "starttime", "", "Start time for generating events (format: dd/mm/yyyy hh:mm).")
	winLoginCmd.Flags().StringVar(&CFG.endTime, "endtime", "", "End time for generating events (format: dd/mm/yyyy hh:mm).")

	// Add flags specific to win_fail
	winFailCmd.Flags().SortFlags = false
	winFailCmd.Flags().IntVarP(&CFG.count, "count", "c", 10, "Number of events to generate")
	winFailCmd.Flags().StringVar(&CFG.domain, "domain", "", "Target domain name")
	winFailCmd.Flags().StringVarP(&CFG.subnet, "subnet", "s", "", "Subnet in which to simulate events")
	winFailCmd.Flags().StringVarP(&CFG.hec_token, "token", "t", "", "HEC token")
	winFailCmd.Flags().StringVarP(&CFG.accountName, "account", "a", "", "Target account name")
	winFailCmd.Flags().StringVar(&CFG.startTime, "starttime", "", "Start time for generating events (format: dd/mm/yyyy hh:mm).")
	winFailCmd.Flags().StringVar(&CFG.endTime, "endtime", "", "End time for generating events (format: dd/mm/yyyy hh:mm).")

	// Add flags specific to win_process
	winProcess.Flags().SortFlags = false
	winProcess.Flags().StringVar(&CFG.domain, "domain", "", "Target domain name")
	winProcess.Flags().StringVar(&CFG.hostname, "hostname", "", "Target hostname")
	winProcess.Flags().StringVar(&CFG.targetIp, "ip", "", "Target ip address")
	winProcess.Flags().StringVar(&CFG.processName, "process", "", "Full path of the process name to execute (fake) on target Windows ( format: C:\\Users\\Public\\Desktop\\mimikatz.exe).")
	winProcess.Flags().StringVar(&CFG.processParameters, "parameters", "", "Parameters to use with process on target Windows. (format:'privilege::debug' 'token::elevate')")
	winProcess.Flags().StringVarP(&CFG.accountName, "account", "a", "", "Target account name")
	winProcess.Flags().StringVarP(&CFG.hec_token, "token", "t", "", "HEC token")
	winProcess.Flags().StringVar(&CFG.execTime, "exectime", "", "Time to execute (fake) on target.")

	// Add flags specific to nix_command
	nixCommand.Flags().SortFlags = false
	nixCommand.Flags().StringVar(&CFG.hostname, "hostname", "", "Target hostname")
	nixCommand.Flags().StringVar(&CFG.targetIp, "ip", "", "Target ip address")
	nixCommand.Flags().StringVar(&CFG.command, "command", "", "Command to execute (fake) on target Nix.")
	nixCommand.Flags().StringVarP(&CFG.hec_token, "token", "t", "", "HEC token")
	nixCommand.Flags().StringVar(&CFG.execTime, "exectime", "", "Time to execute (fake) on target.")

	// Add general flags
	rootCmd.Flags().BoolVarP(&CFG.interactive, "interactive", "i", false, "Run the application in interactive mode")

	// Add other flags relevant to win_login...
	rootCmd.AddCommand(winLoginCmd)
	rootCmd.AddCommand(winProcess)
	rootCmd.AddCommand(winFailCmd)
	rootCmd.AddCommand(interactiveCommand)
	rootCmd.AddCommand(nixCommand)

	// hide default cobra commands:
	completion := completionCommand()
	// mark completion hidden
	completion.Hidden = true
	rootCmd.AddCommand(completion)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
