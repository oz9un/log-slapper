package initialize

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pterm/pterm"
)

type Traffic struct {
	destinationIP string
	localIP       string
}

var (
	dest_ip  string
	local_ip string
	HEC_url  string
)

func capturePackets(iface net.Interface, foundIPs chan<- Traffic, wg *sync.WaitGroup) {
	defer wg.Done()

	// Open the device for capturing.
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v\n", iface.Name, err)
		return
	}
	defer handle.Close()

	// Set the filter to listen for TCP traffic on port 9997.
	if err := handle.SetBPFFilter("tcp and dst port 9997"); err != nil {
		log.Printf("Error setting BPF filter on device %s: %v\n", iface.Name, err)
		return
	}

	// Retrieve local IP addresses for the interface.
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		log.Printf("Error retrieving addresses for device %s: %v\n", iface.Name, err)
		return
	}
	// Extract the IP address without the subnet mask.
	localIP := strings.Split(addrs[0].String(), "/")[0]

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Listen for packets for a limited duration.
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-timeout:
			return
		case packet := <-packetSource.Packets():
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == 9997 {
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer != nil {
						ip, _ := ipLayer.(*layers.IPv4)
						foundIPs <- Traffic{
							destinationIP: ip.DstIP.String(),
							localIP:       localIP,
						}
						return // Stop after finding a relevant packet.
					}
				}
			}
		}
	}
}

func Detect() (localIp string, destIp string) {
	// Initialize pterm multi-printer
	multi := pterm.DefaultMultiPrinter

	// Create a progress bar with a total of 10 units (10 seconds)
	barStyle := pterm.NewStyle(pterm.FgGreen)
	textStyle := pterm.NewStyle(pterm.FgLightBlue) // Style for the text

	pb1, _ := pterm.DefaultProgressbar.
		WithTotal(10).
		WithBarStyle(barStyle).
		WithTitleStyle(textStyle).
		WithWriter(multi.NewWriter()).
		Start("\nDetecting Splunk IP")

	// Start the multi printer
	multi.Start()

	trafficFound := false
	detectedTraffic := []Traffic{} // Slice to store detected traffic

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	foundIPs := make(chan Traffic, 10) // Buffer to hold found IPs.

	// Add a goroutine for updating the progress bar
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			time.Sleep(1 * time.Second) // Wait for a second
			pb1.Increment()             // Increment the progress bar by one
		}
	}()

	for _, iface := range interfaces {
		// Skip interfaces without IP addresses
		if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
			wg.Add(1)
			go capturePackets(iface, foundIPs, &wg)
		}
	}

	// Wait for all goroutines to finish.
	wg.Wait()
	close(foundIPs)

	// Collect detected traffic
	for traffic := range foundIPs {
		detectedTraffic = append(detectedTraffic, traffic)
		trafficFound = true
	}

	// Stop the multi-printer after all operations are done
	multi.Stop()

	// Define a slice for the table data, including headers
	var data [][]string
	// Table headers
	data = append(data, []string{"Local IP", "Splunk IP"})

	// If traffic was found, add it to the data slice for the table
	if trafficFound {

		for _, traffic := range detectedTraffic {
			data = append(data, []string{traffic.localIP, traffic.destinationIP})
			dest_ip = traffic.destinationIP
			local_ip = traffic.localIP
		}
		// Create a table with the data
		// Create and render the table
		table := pterm.TableData(data)
		fmt.Println()
		pterm.DefaultTable.WithHasHeader(true).WithData(table).Render()

	} else {
		// Center print the "no traffic found" message
		noTrafficMessage := pterm.DefaultCenter.WithCenterEachLineSeparately(false).Sprintln("No traffic found on port 9997.")
		pterm.Print(noTrafficMessage)
	}

	HEC_url = "https://" + dest_ip + ":8088/services/collector"

	return local_ip, dest_ip
}
