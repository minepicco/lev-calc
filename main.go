// main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"encoding/csv"
)

const (
	AppDateFormat           = "2006-01-02"
	epssRelevanceWindowDays = 30 // As per CSWP 41 weight function
	epssBaseURL             = "https://api.first.org/data/v1/epss"
)

// --- EPSS API Data Structures ---

type EPSSApiResponseData struct {
	CVE  string `json:"cve"`
	EPSS string `json:"epss"` // EPSS score as a string (e.g., "0.01234")
	Date string `json:"date"`
}

type EPSSApiResponse struct {
	Status     string                `json:"status"`
	StatusCode int                   `json:"status-code"`
	Version    string                `json:"version"`
	Access     string                `json:"access"`
	Total      int                   `json:"total"`
	Offset     int                   `json:"offset"`
	Limit      int                   `json:"limit"`
	Data       []EPSSApiResponseData `json:"data"`
}

// --- CSV Output Data Structure ---

type LEVOutputRecord struct {
	CVE_ID      string
	D0          string
	Dn          string
	LEVScore    float64
	ErrorMsg    string // To record any error during processing for this CVE
	DaysScanned int
	APICalls    int
}

// --- Global Variables (for simplicity in this example) ---
var (
	csvWriter    *csv.Writer
	csvFile      *os.File
	totalAPICalls int = 0
)

// --- Core Functions ---

// FetchEPSSScore fetches the EPSS score for a given CVE on a specific date string (YYYY-MM-DD).
func FetchEPSSScore(cveID string, dateStr string) (float64, error) {
	totalAPICalls++
	url := fmt.Sprintf("%s?cve=%s&date=%s", epssBaseURL, cveID, dateStr)

	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("HTTP request to EPSS API failed for %s on %s: %w", cveID, dateStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Attempt to read body for more details on API error
		// var bodyBytes []byte
		// bodyBytes, _ = io.ReadAll(resp.Body) // Ignoring error from ReadAll for brevity
		return 0, fmt.Errorf("EPSS API request for %s on %s failed with status %s (%d)", cveID, dateStr, resp.Status, resp.StatusCode)
	}

	var apiResponse EPSSApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return 0, fmt.Errorf("failed to decode EPSS API JSON response for %s on %s: %w", cveID, dateStr, err)
	}

	if apiResponse.Total == 0 || len(apiResponse.Data) == 0 {
		// No EPSS data found for this CVE on this date. Treat as 0.
		return 0.0, nil
	}

	epssScoreStr := apiResponse.Data[0].EPSS
	var epssScoreFloat float64
	// fmt.Sscan is simple but float parsing can be tricky. strconv.ParseFloat is more robust.
	if _, err := fmt.Sscan(epssScoreStr, &epssScoreFloat); err != nil {
		return 0, fmt.Errorf("failed to parse EPSS score string '%s' to float for %s on %s: %w", epssScoreStr, cveID, dateStr, err)
	}

	return epssScoreFloat, nil
}

// weightFunction implements weight(di, dn) from the NIST CSWP 41 paper.
func weightFunction(di, dn time.Time) float64 {
	// Normalize dates to midnight UTC for correct day difference calculation
	diNorm := di.Truncate(24 * time.Hour)
	dnNorm := dn.Truncate(24 * time.Hour)

	diffHours := dnNorm.Sub(diNorm).Hours()
	dateDiffDays := int(diffHours / 24)

	// weight is 1 if di is within 30 days of dn (di <= dn AND dn - di < 30 days)
	if dateDiffDays >= 0 && dateDiffDays < epssRelevanceWindowDays {
		return 1.0
	}
	return 0.0
}

// CalculateAndRecordLEV calculates LEV for a single CVE and records the result.
func CalculateAndRecordLEV(cveID, d0Str, dnStr string, dateIncrementDays int) {
	log.Printf("Processing CVE: %s (d0: %s, dn: %s)", cveID, d0Str, dnStr)
	
	var record LEVOutputRecord
	record.CVE_ID = cveID
	record.D0 = d0Str
	record.Dn = dnStr
	
	startTime := time.Now()

	d0, err := time.ParseInLocation(AppDateFormat, d0Str, time.UTC)
	if err != nil {
		errMsg := fmt.Sprintf("invalid start date format for d0 '%s': %v", d0Str, err)
		log.Println(errMsg)
		record.ErrorMsg = errMsg
		writeRecord(record)
		return
	}
	dn, err := time.ParseInLocation(AppDateFormat, dnStr, time.UTC)
	if err != nil {
		errMsg := fmt.Sprintf("invalid end date format for dn '%s': %v", dnStr, err)
		log.Println(errMsg)
		record.ErrorMsg = errMsg
		writeRecord(record)
		return
	}

	if d0.After(dn) {
		errMsg := fmt.Sprintf("start date d0 (%s) cannot be after end date dn (%s)", d0Str, dnStr)
		log.Println(errMsg)
		record.ErrorMsg = errMsg
		writeRecord(record)
		return
	}

	productOfTerms := 1.0
	currentDate := d0
	daysScanned := 0
	initialAPICalls := totalAPICalls

	for !currentDate.After(dn) {
		daysScanned++
		dateStrForAPI := currentDate.Format(AppDateFormat)
		epssScore, fetchErr := FetchEPSSScore(cveID, dateStrForAPI)

		if fetchErr != nil {
			// Log warning, and for calculation, treat this day's EPSS as 0.
			// This means (1 - 0 * weight) = 1, so it doesn't affect the product.
			log.Printf("Warning: Failed to fetch EPSS for %s on %s: %v. Assuming EPSS score 0.0 for this day.", cveID, dateStrForAPI, fetchErr)
			// You might want to collect these errors in record.ErrorMsg
			if record.ErrorMsg == "" {
				record.ErrorMsg = fmt.Sprintf("EPSS fetch error on %s; ", dateStrForAPI)
			} else {
				record.ErrorMsg += fmt.Sprintf("EPSS fetch error on %s; ", dateStrForAPI)
			}
			epssScore = 0.0
		}

		weight := weightFunction(currentDate, dn)
		term := 1.0 - (epssScore * weight)
		productOfTerms *= term

		currentDate = currentDate.AddDate(0, 0, dateIncrementDays)
	}

	levScore := 1.0 - productOfTerms
	record.LEVScore = levScore
	record.DaysScanned = daysScanned
	record.APICalls = totalAPICalls - initialAPICalls


	processingTime := time.Since(startTime)
	log.Printf("LEV for %s (d0=%s, dn=%s): %.4f. Scanned %d days, %d API calls for this CVE. Time: %s",
		cveID, d0Str, dnStr, levScore, record.DaysScanned, record.APICalls, processingTime)
	
	writeRecord(record)
}

// --- CSV Helper Functions ---

func initializeCSV(filePath string) error {
	if filePath == "" {
		return nil // No CSV output requested
	}

	var err error
	csvFile, err = os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output CSV file %s: %w", filePath, err)
	}

	csvWriter = csv.NewWriter(csvFile)
	header := []string{"CVE_ID", "D0", "Dn", "LEV_Score", "Days_Scanned_In_Interval", "API_Calls_For_CVE", "Processing_Error_Messages"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header to %s: %w", filePath, err)
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func writeRecord(record LEVOutputRecord) {
	if csvWriter != nil {
		row := []string{
			record.CVE_ID,
			record.D0,
			record.Dn,
			fmt.Sprintf("%.6f", record.LEVScore),
			fmt.Sprintf("%d", record.DaysScanned),
			fmt.Sprintf("%d", record.APICalls),
			record.ErrorMsg,
		}
		if err := csvWriter.Write(row); err != nil {
			log.Printf("Error writing record to CSV for %s: %v", record.CVE_ID, err)
		}
		// csvWriter.Flush() // Flushing frequently can be slow, flush at end or periodically
	}
}

func closeCSV() {
	if csvWriter != nil {
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			log.Printf("Error flushing CSV writer: %v", err)
		}
	}
	if csvFile != nil {
		if err := csvFile.Close(); err != nil {
			log.Printf("Error closing CSV file: %v", err)
		}
	}
}

// --- Main Function ---

func main() {
	// Setup logging
	log.SetPrefix("LEVCalc: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds) // Added microseconds for timing

	// Command-line flags
	cveIDsStr := flag.String("cves", "", "Comma-separated list of CVE IDs (e.g., CVE-2023-1234,CVE-2021-44228)")
	d0StrFlag := flag.String("d0", "", "Start date for analysis interval (YYYY-MM-DD). If empty, defaults to 90 days before dn.")
	dnStrFlag := flag.String("dn", time.Now().UTC().Format(AppDateFormat), "End date for analysis interval / prediction date (YYYY-MM-DD), defaults to today UTC.")
	outputFilePath := flag.String("o", "", "Output CSV file path (optional).")
	dateIncrement := flag.Int("w", 1, "Date increment step 'w' in days for iterating from d0 to dn (default 1).")

	flag.Parse()

	if *cveIDsStr == "" {
		log.Println("Error: -cves flag is required.")
		flag.Usage()
		os.Exit(1)
	}
	
	finalDnStr := *dnStrFlag
	finalD0Str := *d0StrFlag

	if finalD0Str == "" {
		dnDate, err := time.ParseInLocation(AppDateFormat, finalDnStr, time.UTC)
		if err != nil {
			log.Fatalf("Error parsing default dn date '%s': %v. Please provide dn in YYYY-MM-DD format.", finalDnStr, err)
		}
		finalD0Str = dnDate.AddDate(0, 0, -90).Format(AppDateFormat) // Default d0 to 90 days before dn
		log.Printf("Info: -d0 flag not set, defaulting to %s (%d days before dn %s)", finalD0Str, 90, finalDnStr)
	}


	// Validate d0 and dn format early before processing
	_, errD0 := time.ParseInLocation(AppDateFormat, finalD0Str, time.UTC)
	if errD0 != nil {
		log.Fatalf("Error: Invalid format for -d0 ('%s'). Please use YYYY-MM-DD. %v", finalD0Str, errD0)
	}
	_, errDn := time.ParseInLocation(AppDateFormat, finalDnStr, time.UTC)
	if errDn != nil {
		log.Fatalf("Error: Invalid format for -dn ('%s'). Please use YYYY-MM-DD. %v", finalDnStr, errDn)
	}


	if err := initializeCSV(*outputFilePath); err != nil {
		log.Fatalf("Failed to initialize CSV output: %v", err)
	}
	if *outputFilePath != "" {
		log.Printf("Outputting results to CSV: %s", *outputFilePath)
	}
	defer closeCSV()

	cveIDs := strings.Split(*cveIDsStr, ",")
	
	overallStartTime := time.Now()
	log.Printf("Starting LEV calculation for %d CVE(s)...", len(cveIDs))

	for _, cveID := range cveIDs {
		trimmedCVEID := strings.TrimSpace(cveID)
		if trimmedCVEID == "" {
			continue
		}
		CalculateAndRecordLEV(trimmedCVEID, finalD0Str, finalDnStr, *dateIncrement)
	}
	
	overallTime := time.Since(overallStartTime)
	log.Printf("Finished processing all CVEs. Total API calls: %d. Total time: %s", totalAPICalls, overallTime)
}
