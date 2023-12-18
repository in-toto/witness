package report

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/testifysec/go-witness/intoto"
	"github.com/testifysec/go-witness/source"

	"github.com/jung-kurt/gofpdf"
	"gopkg.in/yaml.v2"
)

type StepData struct {
	StartTime time.Time              `json:"startTime"`
	EndTime   time.Time              `json:"endTime"`
	Data      map[string]interface{} `json:"data"`
}

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

func ProcessVerifiedEvidence(verifiedEvidence map[string][]source.VerifiedCollection, reportConfig ReportConfig) (map[string]StepData, error) {
	stepWiseData := make(map[string]StepData)

	for step, collections := range verifiedEvidence {
		var stepData StepData
		stepData.Data = make(map[string]interface{})

		for _, collection := range collections {
			// Extract the DSSE Envelope
			envelope := collection.Envelope

			// Unmarshal the payload into an intoto.Statement
			payload := &intoto.Statement{}
			if err := json.Unmarshal(envelope.Payload, payload); err != nil {
				return nil, fmt.Errorf("failed to unmarshal intoto.Statement: %w", err)
			}

			// Set the StartTime and EndTime for stepData (assumes you have a way to get these)
			// stepData.StartTime = ...
			// stepData.EndTime = ...

			// Unmarshal the predicate into a parsedCollection
			parsedCollection := &parsedCollection{}
			if err := json.Unmarshal(payload.Predicate, parsedCollection); err != nil {
				return nil, fmt.Errorf("failed to unmarshal parsedCollection: %w", err)
			}

			for _, attestation := range parsedCollection.Attestations {
				attestationType := attestation.Type
				var itemData map[string]interface{}
				err := json.Unmarshal(attestation.Attestation, &itemData)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal attestation data for type %s: %w", attestationType, err)
				}

				if keys, ok := getRelevantKeys(attestationType, reportConfig); ok {
					attestationMap := make(map[string]interface{})
					for _, key := range keys {
						if value, ok := getNestedValue(itemData, key); ok {
							attestationMap[key] = value
						}
						// Missing keys are skipped
					}
					stepData.Data[attestationType] = attestationMap
				}
			}
		}
		stepWiseData[step] = stepData
	}

	return stepWiseData, nil
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

func GeneratePDFReport(stepWiseData map[string]StepData, filename string) error {
	const (
		keyWidth     = 40.0
		valueWidth   = 140.0
		lineHeight   = 6.0
		bottomMargin = 10.0
	)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(false, bottomMargin)
	pdf.AddPage()
	pdf.SetFont("Arial", "", 10)

	for stepName, stepData := range stepWiseData {
		// Step Header
		pdf.SetFont("Arial", "B", 12)
		pdf.CellFormat(0, 10, fmt.Sprintf("Step: %s", stepName), "B", 1, "L", false, 0, "")
		pdf.Ln(8)

		// Time Frame
		startTime := stepData.StartTime.Format(time.RFC3339)
		endTime := stepData.EndTime.Format(time.RFC3339)
		pdf.SetFont("Arial", "I", 10)
		pdf.CellFormat(0, 10, fmt.Sprintf("Time Frame: %s - %s", startTime, endTime), "", 1, "L", false, 0, "")
		pdf.Ln(8)

		// Attestations
		for attestationType, attestationData := range stepData.Data {
			pdf.SetFont("Arial", "U", 10)
			pdf.CellFormat(0, 10, attestationType, "", 1, "L", false, 0, "")
			pdf.Ln(4)

			if dataMap, ok := attestationData.(map[string]interface{}); ok {
				for key, value := range dataMap {
					x, y := pdf.GetXY()

					// Calculate maximum height needed for both key and value cells
					keyHeight := CalculateRowHeight(pdf, key, keyWidth, lineHeight)
					valueHeight := CalculateRowHeight(pdf, fmt.Sprintf("%v", value), valueWidth, lineHeight)
					maxHeight := keyHeight
					if valueHeight > maxHeight {
						maxHeight = valueHeight
					}

					// Check if a new page is needed
					_, pageHeight := pdf.GetPageSize()
					if y+maxHeight > pageHeight-bottomMargin {
						pdf.AddPage()
						y = pdf.GetY()
					}

					// Render Key Cell
					pdf.SetXY(x, y)
					pdf.MultiCell(keyWidth, lineHeight, key, "1", "L", false)

					// Render Value Cell
					pdf.SetXY(x+keyWidth, y)
					pdf.MultiCell(valueWidth, lineHeight, fmt.Sprintf("%v", value), "1", "L", false)

					// Adjust Y position for next row
					pdf.SetXY(x, y+maxHeight)
				}
			}
			pdf.Ln(4)
		}
		pdf.Ln(6)
	}

	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		return err
	}

	return nil
}

// CalculateRowHeight calculates the required height for a MultiCell.
func CalculateRowHeight(pdf *gofpdf.Fpdf, text string, width float64, lineHeight float64) float64 {
	splitText := pdf.SplitLines([]byte(text), width)
	return float64(len(splitText)) * lineHeight
}
