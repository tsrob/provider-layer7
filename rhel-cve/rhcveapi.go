// rhcveapi: A CLI tool for fetching Red Hat CVE data using Cobra.
// Supports input via arguments or a text/CSV file of CVE IDs, with full set of flags from the Python rhsecapi tool.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

const baseURL = "https://access.redhat.com/hydra/rest/securitydata"

// CVEData holds the JSON structure returned by Red Hat API.
type CVEData struct {
	CVE            string `json:"CVE"`
	ThreatSeverity string `json:"ThreatSeverity"`
	PublicDate     string `json:"PublicDate"`
	Bugzilla       []struct {
		ID          int    `json:"id"`
		URL         string `json:"url"`
		Description string `json:"description"`
	} `json:"Bugzilla"`
	CVSS struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vector"`
	} `json:"CVSS"`
	CVSS3 struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vector"`
	} `json:"CVSS3"`
	AffectedRelease []struct {
		ProductName    string `json:"product_name"`
		Cpe            string `json:"cpe"`
		Errata         string `json:"errata"`
		Type           string `json:"type"`
		PublicDate     string `json:"public_date"`
		PackageName    string `json:"package_name,omitempty"`
		PackageVersion string `json:"package_version,omitempty"`
	} `json:"AffectedRelease"`
}

var (
	// Input options
	inputFile string
	cveList   []string
	// Output options
	jsonOutput    bool
	outputType    string
	fields        string
	showAllFields bool
	minimalFields bool
	width         int
	// Concurrency & count
	concurrency int
	countOnly   bool
	threads     int
	// Pastebin and URL
	pastebin bool
	urlOnly  bool
	// Filters (search flags, currently unimplemented)
	qBefore        string
	qAfter         string
	qBug           string
	qAdvisory      string
	qSeverity      string
	qProductFilter string
	qPackageFilter string
	qCwe           string
	qCvss          string
	qCvss3         string
	qEmpty         bool
	qPageSize      int
	qPageNum       int
	qRaw           string
	// Other flags
	iava     string
	optX     bool
	optZero  bool
	logLevel string
	lastDays int
	dryRun   bool
)

// fetchCVE retrieves the CVE data for a given CVE ID.
func fetchCVE(cve string) (*CVEData, error) {
	url := fmt.Sprintf("%s/cve/%s.json", baseURL, cve)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var data CVEData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// readCVEsFromFile reads CVE IDs from a text or CSV file.
func readCVEsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(path))
	var ids []string
	if ext == ".csv" {
		r := csv.NewReader(f)
		recs, err := r.ReadAll()
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if len(rec) > 0 {
				id := strings.TrimSpace(rec[0])
				if id != "" && !strings.EqualFold(id, "CVE") {
					ids = append(ids, id)
				}
			}
		}
	} else {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			id := strings.TrimSpace(scanner.Text())
			if id == "" || strings.EqualFold(id, "CVE") {
				continue
			}
			ids = append(ids, id)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

var rootCmd = &cobra.Command{
	Use:   "rhcveapi [flags] [CVE-IDs...]",
	Short: "Fetch Red Hat CVE data or perform search (search flags are unimplemented)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Aggregate CVE IDs from args and file
		if inputFile != "" {
			fileIDs, err := readCVEsFromFile(inputFile)
			if err != nil {
				return fmt.Errorf("reading CVEs from file: %w", err)
			}
			cveList = append(cveList, fileIDs...)
		}
		cveList = append(cveList, args...)

		// If search filters provided without CVEs, indicate unimplemented
		if len(cveList) == 0 && (qBefore != "" || qAfter != "" || qBug != "" || qAdvisory != "" || qSeverity != "" || qProductFilter != "" || qPackageFilter != "" || qCwe != "" || qCvss != "" || qCvss3 != "" || qEmpty || qRaw != "") {
			fmt.Fprintln(os.Stderr, "Search functionality is not yet implemented.")
			os.Exit(1)
		}
		if len(cveList) == 0 {
			return fmt.Errorf("no CVE IDs specified; provide via args or -F/--file flag")
		}

		// CSV header
		if !jsonOutput && strings.ToLower(outputType) == "csv" {
			fmt.Println("CVE,Severity,Date")
		}

		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, cve := range cveList {
			wg.Add(1)
			go func(cve string) {
				defer wg.Done()
				sem <- struct{}{}
				data, err := fetchCVE(cve)
				<-sem
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching %s: %v\n", cve, err)
					return
				}
				if dryRun {
					fmt.Printf("[dryrun] would fetch %s\n", cve)
					return
				}
				if jsonOutput {
					out, _ := json.MarshalIndent(data, "", "  ")
					fmt.Println(string(out))
					return
				}
				if countOnly {
					fmt.Println(data.CVE)
					return
				}
				// Custom outputs
				switch strings.ToLower(outputType) {
				case "cve":
					fmt.Println(data.CVE)
				case "severity":
					fmt.Printf("%s: %s\n", data.CVE, data.ThreatSeverity)
				case "date":
					fmt.Printf("%s: %s\n", data.CVE, data.PublicDate)
				case "csv":
					fmt.Printf("%s,%s,%s\n", data.CVE, data.ThreatSeverity, data.PublicDate)
				case "all":
					fmt.Printf("%s\n", data.CVE)
					fmt.Printf("  Severity: %s\n", data.ThreatSeverity)
					fmt.Printf("  Public Date: %s\n", data.PublicDate)
					if len(data.Bugzilla) > 0 {
						fmt.Printf("  Bugzilla: %d - %s\n", data.Bugzilla[0].ID, data.Bugzilla[0].URL)
					}
					for _, a := range data.AffectedRelease {
						fmt.Printf("  Affected: %s via %s (%s)\n", a.ProductName, a.Errata, a.PublicDate)
					}
				default:
					fmt.Fprintf(os.Stderr, "Unknown output type '%s', defaulting to 'all'\n", outputType)
					fmt.Println(data.CVE)
				}
				// Pastebin stub
				if pastebin {
					fmt.Fprintf(os.Stderr, "[P] would send output of %s to pastebin\n", cve)
				}
			}(cve)
		}
		wg.Wait()
		return nil
	},
}

func init() {
	// Input
	rootCmd.PersistentFlags().StringVarP(&inputFile, "file", "F", "", "Path to text or CSV file with CVE IDs (one per line or first column)")
	// Output formats
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "Output raw JSON (overrides --output)")
	rootCmd.PersistentFlags().StringVarP(&outputType, "output", "o", "all", "Output field to display: cve, severity, date, all, csv")
	rootCmd.PersistentFlags().StringVar(&fields, "fields", "", "Comma-separated list of fields to display")
	rootCmd.PersistentFlags().BoolVarP(&showAllFields, "all-fields", "a", false, "Alias for --output=all")
	rootCmd.PersistentFlags().BoolVarP(&minimalFields, "minimal", "m", false, "Display minimal fields")
	rootCmd.PersistentFlags().IntVarP(&width, "width", "w", 0, "Set output width for text formatting (0=auto)")
	// Concurrency & count
	rootCmd.PersistentFlags().IntVarP(&concurrency, "concurrency", "c", 5, "Number of concurrent fetches")
	rootCmd.PersistentFlags().BoolVar(&countOnly, "count", false, "Only print CVE IDs (alias for --output=cve)")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 5, "Number of threads (alias for --concurrency)")
	// Pastebin and URL
	rootCmd.PersistentFlags().BoolVarP(&pastebin, "pastebin", "P", false, "Send output to pastebin (stub)")
	rootCmd.PersistentFlags().BoolVarP(&urlOnly, "url", "u", false, "Only print Bugzilla URL")
	// Search filters (unimplemented)
	rootCmd.PersistentFlags().StringVar(&qBefore, "q-before", "", "Search: before date YYYY-MM-DD")
	rootCmd.PersistentFlags().StringVar(&qAfter, "q-after", "", "Search: after date YYYY-MM-DD")
	rootCmd.PersistentFlags().StringVar(&qBug, "q-bug", "", "Search: Bugzilla ID filter")
	rootCmd.PersistentFlags().StringVar(&qAdvisory, "q-advisory", "", "Search: Advisory (RHSA) filter")
	rootCmd.PersistentFlags().StringVar(&qSeverity, "q-severity", "", "Query: severity filter")
	rootCmd.PersistentFlags().StringVar(&qProductFilter, "q-product", "", "Search: product filter")
	rootCmd.PersistentFlags().StringVar(&qPackageFilter, "q-package", "", "Search: package filter")
	rootCmd.PersistentFlags().StringVar(&qCwe, "q-cwe", "", "Search: CWE ID filter")
	rootCmd.PersistentFlags().StringVar(&qCvss, "q-cvss", "", "Search: CVSS score filter")
	rootCmd.PersistentFlags().StringVar(&qCvss3, "q-cvss3", "", "Search: CVSS3 score filter")
	rootCmd.PersistentFlags().BoolVar(&qEmpty, "q-empty", false, "Search: only CVEs with no fix states")
	rootCmd.PersistentFlags().IntVar(&qPageSize, "q-pagesize", 0, "Search: page size for search results")
	rootCmd.PersistentFlags().IntVar(&qPageNum, "q-pagenum", 0, "Search: page number for search results")
	rootCmd.PersistentFlags().StringVar(&qRaw, "q-raw", "", "Search: raw query string")
	// Other flags
	rootCmd.PersistentFlags().StringVarP(&iava, "iava", "i", "", "IAVA identifier for IAVA report")
	rootCmd.PersistentFlags().BoolVar(&optX, "x", false, "Option -x (stub)")
	rootCmd.PersistentFlags().BoolVar(&optZero, "0", false, "Option -0 (stub)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "loglevel", "info", "Log level: debug, info, notice, warning")
	rootCmd.PersistentFlags().IntVar(&lastDays, "E", 0, "Show CVEs from last DAYS")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dryrun", false, "Dry-run mode: do not fetch anything, just print actions")
}

func main() {
	// Alias threads to concurrency
	if threads != 0 {
		concurrency = threads
	}
	if showAllFields {
		outputType = "all"
	}
	if minimalFields {
		outputType = "cve"
	}
	if countOnly {
		outputType = "cve"
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
