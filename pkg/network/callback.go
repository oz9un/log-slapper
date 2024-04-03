package network

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/oz9un/log-slapper/pkg/replacer"
	"github.com/pterm/pterm"
)

func queueCallback(payload *nfqueue.Payload) int {
	// Decode the queued packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	// Check the target packet's application layer/payload:
	if app := packet.ApplicationLayer(); app != nil {
		newPayload := app.Payload()

		realHost, hostReplacement := replacer.HostInfo_originals, replacer.HostInfo_Replacements

		buffer := gopacket.NewSerializeBuffer()
		packetBytes := buffer.Bytes()
		found := false

		for i := 0; i < len(realHost); i++ {
			if strings.Contains(string(app.Payload()), realHost[i]) {
				found = true
				targetString := realHost[i]
				replacementString := hostReplacement[i]

				// If replacement string is shorter than target string, we need to pad it with spaces:
				if len(replacementString) < len(targetString) {
					replacementString = replacementString + strings.Repeat(" ", len(targetString)-len(replacementString))
				}

				// If replacement string is longer than target string, we need to cut it:
				if len(replacementString) > len(targetString) {
					replacementString = replacementString[:len(targetString)]
				}

				// modify payload of application layer: but they gotta be same length:
				*packet.ApplicationLayer().(*gopacket.Payload) = bytes.ReplaceAll(newPayload, []byte(targetString), []byte(replacementString))
				newPayload = packet.ApplicationLayer().(*gopacket.Payload).Payload()

				// if its tcp we need to tell it which network layer is being used
				// to be able to handle multiple protocols we can add a if clause around this
				packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())

				buffer = gopacket.NewSerializeBuffer()
				options := gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}

				// Serialize Packet to get raw bytes
				if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
					log.Fatalln(err)
				}

				packetBytes = buffer.Bytes()

			}
		}

		// check for each target:
		//targets, replacements := commandsReplacements(command)
		for _, cmd := range replacer.GetFalseCommands() {

			targets, replacements := replacer.CommandsReplacements(cmd)

			if containsAllTargets(string(app.Payload()), targets) {
				found = true
				replacer.CommandMap[cmd] = true
				for i := 0; i < len(targets); i++ {
					targetString := targets[i]
					replacementString := replacements[i]

					// If replacement string is shorter than target string, we need to pad it with spaces:
					if len(replacementString) < len(targetString) {
						replacementString = replacementString + strings.Repeat(" ", len(targetString)-len(replacementString))
					}

					// If replacement string is longer than target string, we need to cut it:
					if len(replacementString) > len(targetString) {
						replacementString = replacementString[:len(targetString)]
					}

					if strings.Contains(string(app.Payload()), targetString) {
						// modify payload of application layer: but they gotta be same length:
						*packet.ApplicationLayer().(*gopacket.Payload) = bytes.ReplaceAll(newPayload, []byte(targetString), []byte(replacementString))
						newPayload = packet.ApplicationLayer().(*gopacket.Payload).Payload()

						// Create a logger with a level of Trace or higher.
						logger := pterm.DefaultLogger.WithLevel(pterm.LogLevelTrace)

						// Create a map of interesting stuff.
						interstingStuff := map[string]any{
							"Target string":      targetString,
							"Replacement string": replacementString,
						}

						// Log a debug message with arguments from a map.
						fmt.Println()
						logger.Info("Packet found with target data inside!", logger.ArgsFromMap(interstingStuff))

						// if its tcp we need to tell it which network layer is being used
						// to be able to handle multiple protocols we can add a if clause around this
						packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())

						buffer = gopacket.NewSerializeBuffer()
						options := gopacket.SerializeOptions{
							ComputeChecksums: true,
							FixLengths:       true,
						}

						// Serialize Packet to get raw bytes
						if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
							log.Fatalln(err)
						}

						packetBytes = buffer.Bytes()

					}
				}
			}
		}

		if found {
			payload.SetVerdictModified(nfqueue.NF_ACCEPT, packetBytes)
		}
	}

	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func containsAllTargets(payload string, targets []string) bool {
	// Iterate through each target string
	for _, target := range targets {
		// Check if the target string is not present in the payload
		if !strings.Contains(payload, target) {
			return false
		}
	}
	// All targets are present in the payload
	return true
}
