package splunk

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config represents the top-level configuration structure
type Config struct {
	Splunk      SplunkSettings    `yaml:"splunk"`
	Log         LogSettings       `yaml:"log"`
	ExtraFields map[string]string `yaml:"extra_fields"` // Adjusted to be at the root level
	Events      []EventSettings   `yaml:"events"`       // Adjusted to a slice of EventSettings}
}

// SplunkSettings holds Splunk specific configurations
type SplunkSettings struct {
	TargetIP   string `yaml:"target_ip"`
	TargetPort string `yaml:"target_port"`
}

// LogSettings holds the settings for the log data
type LogSettings struct {
	Index      string `yaml:"index"`
	Source     string `yaml:"source"`
	Sourcetype string `yaml:"sourcetype"`
	Hostname   string `yaml:"hostname"`
}

// EventSettings holds the configuration for log events
type EventSettings struct {
	Time string `yaml:"time"`
	Data string `yaml:"data"`
}

// ProcessConfigFile takes a YAML configuration file as input, parses it, and stores the data in variables
func ProcessConfigFile(filePath string) (*Config, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	/*
			// Print out all details from the configuration
			fmt.Println("Splunk Configuration:")
			fmt.Printf("  Target IP: %s\n", config.Splunk.TargetIP)
			fmt.Printf("  Target Port: %d\n", config.Splunk.TargetPort)

			fmt.Println("Log Configuration:")
			fmt.Printf("  Index: %s\n", config.Log.Index)
			fmt.Printf("  Source: %s\n", config.Log.Source)
			fmt.Printf("  Sourcetype: %s\n", config.Log.Sourcetype)
			fmt.Printf("  Hostname: %s\n", config.Log.Hostname)


		if len(config.ExtraFields) > 0 {
			fmt.Println("Extra Fields:")
			for key, value := range config.ExtraFields {
				fmt.Printf("  %s: %s\n", key, value)
			}
		} else {
			fmt.Println("No extra fields provided.")
		}

		fmt.Println("Event Configuration:")
		fmt.Printf("  Time: %s\n", config.Event.Time)
		fmt.Println("Event Data:")
		for _, line := range strings.Split(config.Event.Data, "\n") {
			fmt.Println(line)
		}
	*/

	return &config, nil
}

/*
func main() {
	configFilePath := "log.yaml"
	_, err := ProcessConfigFile(configFilePath)
	if err != nil {
		log.Fatalf("Error processing config file: %v", err)
	}
	// The rest of your application logic goes here...
}
*/
