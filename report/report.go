package report

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/source"

	"github.com/jung-kurt/gofpdf"
	"gopkg.in/yaml.v2"
)

type StepData struct {
	StartTime time.Time              `json:"startTime"`
	EndTime   time.Time              `json:"endTime"`
	Data      map[string]interface{} `json:"data"`
	Signers   []Functionary          `json:"signers"`
}

type Functionary struct {
	//Important fields from the certificate
	CommonName    string    `json:"commonName"`
	Email         string    `json:"email"`
	URI           string    `json:"uri"`
	CACommonName  string    `json:"caCommonName"`
	TimeStampedAt time.Time `json:"timeStampedAt"`
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
			// Extract the DSSE Envelope and process signers
			envelope := collection.Envelope

			// signers := collection.Envelope.Signatures
			// // var signers []dsse.Signature

			// for _, signer := range signers {
			// 	break
			// 	// Decode the PEM block
			// 	block, _ := pem.Decode(signer.Certificate)
			// 	if block == nil {
			// 		//dont error out, just skip this signer
			// 		break

			// 		//return nil, fmt.Errorf("failed to decode PEM block")
			// 	}

			// 	var functionary Functionary

			// 	// Check if the block is a certificate
			// 	if block.Type == "CERTIFICATE" {
			// 		// Parse the certificate
			// 		cert, err := x509.ParseCertificate(block.Bytes)
			// 		if err != nil {
			// 			return nil, fmt.Errorf("failed to parse certificate: %w", err)
			// 		}

			// 		functionary.CACommonName = cert.Issuer.CommonName
			// 		functionary.CommonName = cert.Subject.CommonName

			// 		// Handle EmailAddresses
			// 		if len(cert.EmailAddresses) > 0 {
			// 			functionary.Email = cert.EmailAddresses[0]
			// 		} else {
			// 			functionary.Email = "N/A"
			// 		}

			// 		// Handle URIs
			// 		if len(cert.URIs) > 0 {
			// 			functionary.URI = cert.URIs[0].String()
			// 		} else {
			// 			functionary.URI = "N/A"
			// 		}
			// 	} else if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
			// 		// Handle public key
			// 		_, err := x509.ParsePKIXPublicKey(block.Bytes)
			// 		if err != nil {
			// 			return nil, fmt.Errorf("failed to parse public key: %w", err)
			// 		}
			// 		// You can now use publicKey for your purposes
			// 		// For example, setting common name as "Public Key"
			// 		functionary.CommonName = "Public Key"
			// 		functionary.Email = "N/A"
			// 		functionary.URI = "N/A"
			// 	} else {
			// 		return nil, fmt.Errorf("unknown PEM block type")
			// 	}

			// 	stepData.Signers = append(stepData.Signers, functionary)
			// }

			// Unmarshal the payload into an intoto.Statement
			payload := &intoto.Statement{}
			if err := json.Unmarshal(envelope.Payload, payload); err != nil {
				return nil, fmt.Errorf("failed to unmarshal intoto.Statement: %w", err)
			}

			//parse attestation data into attestationData struct

			// Unmarshal the predicate into a parsedCollection
			parsedCollection := &parsedCollection{}
			if err := json.Unmarshal(payload.Predicate, parsedCollection); err != nil {
				return nil, fmt.Errorf("failed to unmarshal parsedCollection: %w", err)
			}

			for _, attestation := range parsedCollection.Attestations {
				var itemData map[string]interface{}
				if err := json.Unmarshal(attestation.Attestation, &itemData); err != nil {
					return nil, fmt.Errorf("failed to unmarshal attestation data for type %s: %w", attestation.Type, err)
				}

				startTime, err := time.Parse(time.RFC3339Nano, attestation.StartTime)
				if err != nil {
					return nil, fmt.Errorf("failed to parse attestation start time: %w", err)
				}

				endTime, err := time.Parse(time.RFC3339Nano, attestation.EndTime)
				if err != nil {
					return nil, fmt.Errorf("failed to parse attestation end time: %w", err)
				}

				// Process attestation data based on attestation type
				attestationType := attestation.Type
				if keys, ok := getRelevantKeys(attestationType, reportConfig); ok {
					attestationMap := make(map[string]interface{})
					for _, key := range keys {
						if value, ok := getNestedValue(itemData, key); ok {
							attestationMap[key] = value
						}
					}
					stepData.Data[attestationType] = attestationMap
					stepData.StartTime = startTime
					stepData.EndTime = endTime
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
		StartTime   string          `json:"starttime"`
		EndTime     string          `json:"endtime"`
	} `json:"attestations"`
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
		renderStepHeader(pdf, stepName)
		renderTimeFrame(pdf, stepData.StartTime, stepData.EndTime)
		renderFunctionaries(pdf, stepData.Signers)

		for attestationType, attestationData := range stepData.Data {
			renderAttestationHeader(pdf, attestationType)

			if dataMap, ok := attestationData.(map[string]interface{}); ok {
				for key, value := range dataMap {
					// Convert value to a string, handling different possible types
					valueStr := formatValue(value)
					renderRow(pdf, key, valueStr, keyWidth, valueWidth, lineHeight, bottomMargin)
				}
			}
			pdf.Ln(4) // Space after each attestation
		}

		pdf.Ln(6) // Space after each step
	}

	return pdf.OutputFileAndClose(filename)
}

func renderStepHeader(pdf *gofpdf.Fpdf, stepName string) {
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(0, 10, fmt.Sprintf("Step: %s", stepName), "B", 1, "L", false, 0, "")
	pdf.Ln(8)
}

func renderTimeFrame(pdf *gofpdf.Fpdf, startTime, endTime time.Time) {
	timeFormat := time.RFC3339
	pdf.SetFont("Arial", "I", 10)
	pdf.CellFormat(0, 10, fmt.Sprintf("Time Frame: %s - %s", startTime.Format(timeFormat), endTime.Format(timeFormat)), "", 1, "L", false, 0, "")
	pdf.Ln(8)
}

func renderAttestationHeader(pdf *gofpdf.Fpdf, attestationType string) {
	pdf.SetFont("Arial", "U", 10)
	pdf.CellFormat(0, 10, attestationType, "", 1, "L", false, 0, "")
	pdf.Ln(4)
}

func renderRow(pdf *gofpdf.Fpdf, key, value string, keyWidth, valueWidth, lineHeight, bottomMargin float64) {
	x, y := pdf.GetXY()
	_, pageHeight := pdf.GetPageSize()
	maxHeight := getMaxHeight(pdf, key, value, keyWidth, valueWidth, lineHeight)

	// Add new page if needed
	if y+maxHeight > pageHeight-bottomMargin {
		pdf.AddPage()
		y = pdf.GetY()
	}

	// Render Key Cell
	pdf.SetXY(x, y)
	pdf.MultiCell(keyWidth, lineHeight, key, "1", "L", false)

	// Render Value Cell
	pdf.SetXY(x+keyWidth, y)
	pdf.MultiCell(valueWidth, lineHeight, value, "1", "L", false)

	// Adjust Y position for next row
	pdf.SetXY(x, y+maxHeight)
}

func getMaxHeight(pdf *gofpdf.Fpdf, key, value string, keyWidth, valueWidth, lineHeight float64) float64 {
	keyHeight := CalculateRowHeight(pdf, key, keyWidth, lineHeight)
	valueHeight := CalculateRowHeight(pdf, value, valueWidth, lineHeight)
	if valueHeight > keyHeight {
		return valueHeight
	}
	return keyHeight
}

// CalculateRowHeight calculates the required height for a MultiCell.
func CalculateRowHeight(pdf *gofpdf.Fpdf, text string, width, lineHeight float64) float64 {
	splitText := pdf.SplitLines([]byte(text), width)
	return float64(len(splitText)) * lineHeight
}

func formatValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case float64, float32, int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%v", v)
	case []string:
		return strings.Join(v, ", ")
	case []interface{}:
		var strSlice []string
		for _, item := range v {
			strSlice = append(strSlice, fmt.Sprintf("%v", item))
		}
		return strings.Join(strSlice, " ")
	default:
		return fmt.Sprintf("%v", v) // Fallback for other types
	}
}

func renderFunctionaries(pdf *gofpdf.Fpdf, signers []Functionary) {
	if len(signers) == 0 {
		return
	}

	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(0, 10, "Functionaries:", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	for _, signer := range signers {
		pdf.CellFormat(0, 6, fmt.Sprintf("Common Name: %s", signer.CommonName), "", 1, "L", false, 0, "")
		pdf.CellFormat(0, 6, fmt.Sprintf("Email: %s", signer.Email), "", 1, "L", false, 0, "")
		pdf.CellFormat(0, 6, fmt.Sprintf("URI: %s", signer.URI), "", 1, "L", false, 0, "")
		pdf.CellFormat(0, 6, fmt.Sprintf("CA Common Name: %s", signer.CACommonName), "", 1, "L", false, 0, "")
		pdf.CellFormat(0, 6, fmt.Sprintf("Timestamp: %s", signer.TimeStampedAt.Format(time.RFC3339)), "", 1, "L", false, 0, "")
		pdf.Ln(4) // Extra space after each functionary
	}

	pdf.Ln(6) // Space after all functionaries
}

// Helper function to process attestation times
func processAttestationTimes(itemData map[string]interface{}, stepData StepData) StepData {
	if startTimeStr, ok := itemData["starttime"].(string); ok {
		if startTime, err := time.Parse(time.RFC3339Nano, startTimeStr); err == nil {
			if stepData.StartTime.IsZero() || startTime.Before(stepData.StartTime) {
				stepData.StartTime = startTime
			}
		}
	}

	if endTimeStr, ok := itemData["endtime"].(string); ok {
		if endTime, err := time.Parse(time.RFC3339Nano, endTimeStr); err == nil {
			if stepData.EndTime.IsZero() || endTime.After(stepData.EndTime) {
				stepData.EndTime = endTime
			}
		}
	}

	return stepData
}
