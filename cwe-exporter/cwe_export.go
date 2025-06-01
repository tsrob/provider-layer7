// cwe_export.go
//
// Downloads the latest MITRE CWE XML (packed as XML.zip) from MITRE’s official “Downloads” page
// (conforming to CWE Schema 7.2). Unpacks the ZIP in memory, locates the CWE XML file,
// and parses it using the provided XSD structure (namespace "http://cwe.mitre.org/cwe-7").
// Iterates through each CWE entry under <Weakness_Catalog><Weaknesses><Weakness> and extracts:
//   - ID (attribute)
//   - Name (attribute)
//   - Description (element)
//   - Extended_Description (element), cleaned to a single line; if absent, a ChildOf reference from <Related_Weaknesses>
//   - Potential_Mitigations (under <Potential_Mitigations><Mitigation><Description>), cleaned of newlines,
//     each mitigation on a single line, multiple mitigations separated by semicolons
//   - If no Potential_Mitigations, inherit from ChildOf reference's mitigations
// Writes out all compiled data into a new CSV file (`output.csv`) for easy viewing.
//
// To initialize the Go module and run:
// 1. Create a directory and place this file (`cwe_export.go`) inside.
// 2. In terminal, navigate to that directory.
// 3. Initialize a module, e.g.:
//      go mod init example.com/cweexport
// 4. Build/run:
//      go run cwe_export.go
//    or to build an executable:
//      go build -o cwe_export
//      ./cwe_export

package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// WeaknessCatalog corresponds to <Weakness_Catalog> in namespace "http://cwe.mitre.org/cwe-7".
type WeaknessCatalog struct {
	XMLName    xml.Name         `xml:"http://cwe.mitre.org/cwe-7 Weakness_Catalog"`
	Weaknesses WeaknessesHolder `xml:"http://cwe.mitre.org/cwe-7 Weaknesses"`
}

// WeaknessesHolder wraps multiple <Weakness> elements.
type WeaknessesHolder struct {
	WeaknessList []Weakness `xml:"http://cwe.mitre.org/cwe-7 Weakness"`
}

// Weakness maps to <Weakness> entries.
type Weakness struct {
	ID                    string                         `xml:"ID,attr"`
	Name                  string                         `xml:"Name,attr"`
	Description           string                         `xml:"http://cwe.mitre.org/cwe-7 Description"`
	ExtendedDescription   string                         `xml:"http://cwe.mitre.org/cwe-7 Extended_Description>http://www.w3.org/1999/xhtml p"`
	PotentialMitsHolder   PotentialMitigationsHolder     `xml:"http://cwe.mitre.org/cwe-7 Potential_Mitigations"`
	RelatedWeaknessesHolder RelatedWeaknessesHolder      `xml:"http://cwe.mitre.org/cwe-7 Related_Weaknesses"`
}

// PotentialMitigationsHolder holds zero or more <Mitigation> elements.
type PotentialMitigationsHolder struct {
	Mitigations []Mitigation `xml:"http://cwe.mitre.org/cwe-7 Mitigation"`
}

// Mitigation corresponds to each <Mitigation> element.
type Mitigation struct {
	Description string `xml:"http://cwe.mitre.org/cwe-7 Description"`
}

// RelatedWeaknessesHolder holds zero or more <Related_Weakness> elements.
type RelatedWeaknessesHolder struct {
	Related []RelatedWeakness `xml:"http://cwe.mitre.org/cwe-7 Related_Weakness"`
}

// RelatedWeakness maps to <Related_Weakness> entries.
type RelatedWeakness struct {
	Nature string `xml:"Nature,attr"`
	CWEID  string `xml:"CWE_ID,attr"`
}

// CWEEntry holds the extracted fields for CSV output.
type CWEEntry struct {
	ID                  string
	Name                string
	Description         string
	ExtendedDescription string
	Mitigations         string
}

func main() {
	zipURL := "https://cwe.mitre.org/data/xml/cwec_v4.17.xml.zip"

	fmt.Println("Downloading CWE XML.zip from MITRE...")
	zipData, err := downloadFile(zipURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading ZIP: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Download complete. Size:", len(zipData), "bytes")

	fmt.Println("Unzipping in memory...")
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ZIP data: %v\n", err)
		os.Exit(1)
	}

	var xmlReader io.ReadCloser
	for _, f := range reader.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening inner XML %s: %v\n", f.Name, err)
				os.Exit(1)
			}
			xmlReader = rc
			fmt.Println("Found XML inside ZIP:", f.Name)
			break
		}
	}
	if xmlReader == nil {
		fmt.Fprintln(os.Stderr, "No XML file found inside zip archive")
		os.Exit(1)
	}
	defer xmlReader.Close()

	xmlBytes, err := ioutil.ReadAll(xmlReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading XML: %v\n", err)
		os.Exit(1)
	}

	var catalog WeaknessCatalog
	if err := xml.Unmarshal(xmlBytes, &catalog); err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling XML: %v\n", err)
		os.Exit(1)
	}

	// Build a map for lookup: ID -> Weakness
	weakMap := make(map[string]Weakness)
	for _, w := range catalog.Weaknesses.WeaknessList {
		weakMap[w.ID] = w
	}

	var entries []CWEEntry
	for i, w := range catalog.Weaknesses.WeaknessList {
		// Determine Extended Description
		exRaw := w.ExtendedDescription
		// Remove line breaks and carriage returns, collapse to one line
		exRawClean := strings.ReplaceAll(strings.ReplaceAll(exRaw, "\n", " "), "\r", " ")
		extDesc := strings.TrimSpace(exRawClean)
		if extDescTrim := extDesc; extDescTrim == "" {
			// No extended; find a ChildOf in RelatedWeaknesses
			for _, rel := range w.RelatedWeaknessesHolder.Related {
				if rel.Nature == "ChildOf" {
					extDesc = rel.CWEID
					break
				}
			}
		}

		// Determine Mitigations
		var mitList []string
		for _, m := range w.PotentialMitsHolder.Mitigations {
			trimmed := strings.TrimSpace(m.Description)
			if trimmed != "" {
				// Replace any newline or carriage return inside content with space
				clean := strings.ReplaceAll(strings.ReplaceAll(trimmed, "\n", " "), "\r", " ")
				mitList = append(mitList, clean)
			}
		}
		// If no mitigations, look up ChildOf reference
		if len(mitList) == 0 {
			for _, rel := range w.RelatedWeaknessesHolder.Related {
				if rel.Nature == "ChildOf" {
					if parent, ok := weakMap[rel.CWEID]; ok {
						for _, pm := range parent.PotentialMitsHolder.Mitigations {
							trimmed := strings.TrimSpace(pm.Description)
							if trimmed != "" {
								clean := strings.ReplaceAll(strings.ReplaceAll(trimmed, "\n", " "), "\r", " ")
								mitList = append(mitList, clean)
							}
						}
						break
					}
				}
			}
		}
		mitStr := strings.Join(mitList, "; ")

		entries = append(entries, CWEEntry{
			ID:                  w.ID,
			Name:                w.Name,
			Description:         strings.TrimSpace(w.Description),
			ExtendedDescription: extDesc,
			Mitigations:         mitStr,
		})

		if (i+1)%100 == 0 {
			fmt.Printf("Processed %d entries...\n", i+1)
		}
	}

	outFile := "output.csv"
	fmt.Println("Writing data to", outFile)
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	header := []string{"CWE_ID", "Name", "Description", "Extended_Description", "Mitigations"}
	if err := w.Write(header); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing header to output: %v\n", err)
		os.Exit(1)
	}

	for _, e := range entries {
		row := []string{e.ID, e.Name, e.Description, e.ExtendedDescription, e.Mitigations}
		if err := w.Write(row); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing row to output CSV: %v\n", err)
			os.Exit(1)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing to output CSV: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done! CWE data stored in", outFile)
}

func downloadFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Unexpected HTTP status: %s", resp.Status)
	}
	return ioutil.ReadAll(resp.Body)
}

func indexMap(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, col := range header {
		key := strings.TrimSpace(col)
		key = strings.ReplaceAll(key, " ", "_")
		m[key] = i
	}
	return m
}
