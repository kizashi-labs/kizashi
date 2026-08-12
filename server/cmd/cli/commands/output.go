package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// printTable prints rows as an aligned table.
// headers is a slice of column names; rows is a slice of string slices.
func printTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	fmt.Fprintln(w, strings.Repeat("-\t", len(headers)))
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

// printJSON prints v as indented JSON.
func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// printCSV prints rows as CSV with headers.
func printCSV(headers []string, rows [][]string) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write(headers)
	for _, row := range rows {
		_ = w.Write(row)
	}
	w.Flush()
}

// printOutput dispatches to the appropriate printer based on --output flag.
func printOutput(headers []string, rows [][]string, raw interface{}) {
	switch outFmt() {
	case "json":
		printJSON(raw)
	case "csv":
		printCSV(headers, rows)
	default:
		printTable(headers, rows)
	}
}
