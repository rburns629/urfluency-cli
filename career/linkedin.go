package career

import (
	"archive/zip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// A LinkedIn data export ("Get a copy of your data") is a zip that can also
// hold messages, connections, and contacts. ReadExport opens only Profile.csv
// and Positions.csv, and of Profile.csv reads only the name, headline, and
// summary: never the address or birth date beside them.

// maxCSV bounds how much of each file is read, against a zip that expands
// into far more than it holds.
const maxCSV = 4 << 20

// ReadExport reads a LinkedIn export zip.
func ReadExport(zipPath string) (Profile, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return Profile{}, fmt.Errorf("open the LinkedIn export: %w", err)
	}
	defer zr.Close()
	var profile, positions *zip.File
	for _, f := range zr.File {
		switch strings.ToLower(path.Base(f.Name)) {
		case "profile.csv":
			profile = f
		case "positions.csv":
			positions = f
		}
	}
	if positions == nil {
		return Profile{}, errors.New("the export has no Positions.csv; request it again with your profile data selected")
	}
	var p Profile
	if profile != nil {
		rows, err := readCSV(profile)
		if err != nil {
			return Profile{}, fmt.Errorf("read Profile.csv: %w", err)
		}
		if len(rows) > 0 {
			r := rows[0]
			p.Name = strings.TrimSpace(r["first name"] + " " + r["last name"])
			p.Headline, p.Summary = r["headline"], r["summary"]
		}
	}
	rows, err := readCSV(positions)
	if err != nil {
		return Profile{}, fmt.Errorf("read Positions.csv: %w", err)
	}
	for i, r := range rows {
		start, err := exportMonth(r["started on"])
		if err != nil {
			return Profile{}, fmt.Errorf("row %d of Positions.csv: start date: %w", i+2, err)
		}
		end := ""
		if v := strings.TrimSpace(r["finished on"]); v != "" {
			if end, err = exportMonth(v); err != nil {
				return Profile{}, fmt.Errorf("row %d of Positions.csv: end date: %w", i+2, err)
			}
		}
		p.Positions = append(p.Positions, Position{ID: fmt.Sprintf("r%d", i+1), Title: strings.TrimSpace(r["title"]),
			Company: strings.TrimSpace(r["company name"]), Description: strings.TrimSpace(r["description"]), Start: start, End: end})
	}
	if len(p.Positions) == 0 {
		return Profile{}, errors.New("the export's Positions.csv lists no positions")
	}
	return p, nil
}

// readCSV reads a CSV file into rows keyed by lowercase header.
func readCSV(f *zip.File) ([]map[string]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxCSV+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCSV {
		return nil, fmt.Errorf("over %d MB", maxCSV>>20)
	}
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := records[0]
	var rows []map[string]string
	for _, rec := range records[1:] {
		row := map[string]string{}
		for i, h := range header {
			if i < len(rec) {
				row[strings.ToLower(strings.TrimSpace(h))] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// exportMonth reads the export's dates, "Mar 2024" or "2024", as "2024-03"
// (January when only the year is given).
func exportMonth(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"Jan 2006", "January 2006", "2006-01", "01/2006", "2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("2006-01"), nil
		}
	}
	return "", fmt.Errorf("unreadable date %q", s)
}
