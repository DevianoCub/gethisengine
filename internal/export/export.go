// Package export renders extracted data as tables, JSON or CSV.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Table is a simple header/rows representation used by the text and CSV
// renderers.
type Table struct {
	Headers []string
	Rows    [][]string
}

// WriteTable renders an aligned plain-text table.
func WriteTable(w io.Writer, table Table) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if len(table.Headers) > 0 {
		if _, err := fmt.Fprintln(tw, strings.Join(table.Headers, "\t")); err != nil {
			return err
		}
	}
	for _, row := range table.Rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// WriteCSV renders the table as RFC 4180 CSV.
func WriteCSV(w io.Writer, table Table) error {
	cw := csv.NewWriter(w)
	cw.UseCRLF = false
	if err := cw.Write(table.Headers); err != nil {
		return err
	}
	for _, row := range table.Rows {
		safe := make([]string, len(row))
		for i, cell := range row {
			safe[i] = csvSafe(cell)
		}
		if err := cw.Write(safe); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteJSON writes indented JSON with a trailing newline.
func WriteJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

// csvSafe prevents spreadsheet formula injection when a cell starts with a
// character that Excel/LibreOffice interpret as a formula.
func csvSafe(cell string) string {
	if cell == "" {
		return cell
	}
	switch cell[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + cell
	}
	return cell
}

// Mask replaces a secret with a fixed-width placeholder so that its length is
// not leaked either.
func Mask(secret string) string {
	if secret == "" {
		return ""
	}
	return "********"
}

// Time formats a timestamp for text and CSV output.
func Time(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// Bytes formats a size for display.
func Bytes(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := int64(n) / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
