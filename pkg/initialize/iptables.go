package initialize

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/pterm/pterm"
)

// IPtables initialization part:
func IptablesInit() {
	sourcePort := "9997"

	//Set iptables rule to route packets from source port 9997 to queue number 0
	cmd := exec.Command("iptables", "-t", "raw", "-I", "OUTPUT", "-p", "tcp", "--destination-port", sourcePort, "-j", "NFQUEUE", "--queue-num", "0")
	_, err := cmd.Output()

	if err != nil {
		pterm.Error.Println("Failed to initialize iptables rule: " + err.Error())
		return
	} else {

	}
	time.Sleep(10 * time.Second) // wait for changes

}

func IptablesRemove() {

	spinner, _ := pterm.DefaultSpinner.Start("Removing all IP routing rules. Please wait...")
	unroute := exec.Command("iptables", "-F", "-t", "raw")
	time.Sleep(2 * time.Second)

	stdoutUnroute, err := unroute.Output()

	spinner.Success("IPTables are cleared.")

	if err != nil {
		pterm.Error.Println("Failed to remove iptables rule: " + err.Error())
		return
	} else {
		fmt.Println(string(stdoutUnroute))
	}
}
