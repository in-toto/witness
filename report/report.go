package report

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/testifysec/go-witness/intoto"
	"github.com/testifysec/go-witness/source"
	"gopkg.in/yaml.v2"
)

type ReportConfig struct {
	Title        string            `yaml:"title"`
	StepsSummary bool              `yaml:"steps_summary"`
	Attestations []AttestationInfo `yaml:"attestations"`
}

// AttestationInfo holds information about each attestation in the report.
type AttestationInfo struct {
	ID     string   `yaml:"id"`
	URL    string   `yaml:"url"`
	Fields []string `yaml:"fields"`
}

func ProcessVerifiedEvidence(verifiedEvidence map[string][]source.VerifiedCollection, reportConfig ReportConfig) (map[string]map[string]interface{}, error) {
	keyValuePairs := make(map[string]map[string]interface{})

	for _, collections := range verifiedEvidence {
		for _, collection := range collections {
			// Extract the DSSE Envelope
			envelope := collection.Envelope

			// Unmarshal the payload into an intoto.Statement
			payload := &intoto.Statement{}
			if err := json.Unmarshal(envelope.Payload, payload); err != nil {
				return nil, fmt.Errorf("failed to unmarshal intoto.Statement: %w", err)
			}

			// Unmarshal the predicate into a parsedCollection
			parsedCollection := &parsedCollection{}
			if err := json.Unmarshal(payload.Predicate, parsedCollection); err != nil {
				return nil, fmt.Errorf("failed to unmarshal parsedCollection: %w", err)
			}

			for _, attestation := range parsedCollection.Attestations {
				attestationType := attestation.Type
				// Unmarshal the attestation data into a generic map
				var itemData map[string]interface{}
				err := json.Unmarshal(attestation.Attestation, &itemData)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal attestation data for type %s: %w", attestationType, err)
				}

				// Process the attestation data based on the report configuration
				if keys, ok := getRelevantKeys(attestationType, reportConfig); ok {
					if _, exists := keyValuePairs[attestationType]; !exists {
						keyValuePairs[attestationType] = make(map[string]interface{})
					}
					for _, key := range keys {
						value, ok := getNestedValue(itemData, key)
						if !ok {
							return nil, fmt.Errorf("key %s not found in attestation type %s", key, attestationType)
						}
						keyValuePairs[attestationType][key] = value
					}
				}
			}
		}
	}

	return keyValuePairs, nil
}

// Ensure parsedCollection struct is defined to match your attestation structure
type parsedCollection struct {
	Attestations []struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	} `json:"attestations"`
}

type attestationData struct {
	Type string
	Data []byte // Replace with the actual data field
}

func getNestedValue(data map[string]interface{}, key string) (interface{}, bool) {
	keys := strings.Split(key, ".")
	var current interface{} = data

	for _, k := range keys {
		if currentMap, ok := current.(map[string]interface{}); ok {
			current, ok = currentMap[k]
			if !ok {
				return nil, false // Key not found at this level
			}
		} else {
			return nil, false // Not a map where we expect it to be
		}
	}

	return current, true
}

// getRelevantKeys finds the relevant keys for an attestation type based on the report configuration.
func getRelevantKeys(attestationType string, config ReportConfig) ([]string, bool) {
	for _, attestation := range config.Attestations {
		//debug
		fmt.Println(attestation.ID)
		fmt.Println(attestationType)
		fmt.Println(attestation.ID == attestationType)

		if attestation.ID == attestationType {

			return attestation.Fields, true
		}
	}
	return nil, false
}

// LoadReportConfig reads the YAML configuration file and unmarshals it into a ReportConfig struct.
func LoadReportConfig(filePath string) (ReportConfig, error) {
	var config ReportConfig

	// Read the YAML file
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return config, err
	}

	// Unmarshal the YAML file into the ReportConfig struct
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
