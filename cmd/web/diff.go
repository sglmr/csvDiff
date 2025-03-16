package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
)

type mismatch struct {
	key     string
	field   string
	file1   string
	file2   string
	message string
}

// findMismatches takes in two multipart CSV files from a HTTP form and returns a multipart file of mismatches
func findMismatches(logger *slog.Logger, file1, file2 io.Reader, key, file1Name, file2Name string) ([]byte, error) {
	logger.Debug("starting csvdiff", "key", key)

	mismatches := []mismatch{}

	// Read the file1 file data
	file1Data, err := csvFileToSliceMap(file1, key)
	if err != nil {
		return nil, fmt.Errorf("file1 csv to map: %w", err)
	}

	// Read the file2 file
	file2Data, err := csvFileToSliceMap(file2, key)
	if err != nil {
		return nil, fmt.Errorf("file1 csv to map: %w", err)
	}
	// Log record counts
	logger.Debug("read input files", "file1 count", len(file1Data), "file2 count", len(file2Data))

	// Compare file1 fields to file2
	file1Data, m := normalizeColumns(file1Data, getFieldNames(file2Data[0]), file1Name)
	mismatches = append(mismatches, m...)
	logger.Debug("checked for extra fields on file1 file", "mismatch count", len(mismatches))

	// Compare file2 fields to file1.
	file2Data, m = normalizeColumns(file2Data, getFieldNames(file1Data[0]), file2Name)
	mismatches = append(mismatches, m...)
	logger.Debug("checked for extra fields on file2 file", "mismatch count", len(mismatches))

	// Remove duplicate in file1 file.
	file1Data, m = deDuplicate(file1Data, key, file1Name)
	mismatches = append(mismatches, m...)
	logger.Debug("checked for duplicate records on file1 file", "mismatch count", len(mismatches))

	// Remove duplicate in file2 file.
	file2Data, m = deDuplicate(file2Data, key, file2Name)
	mismatches = append(mismatches, m...)
	logger.Debug("checked for duplicate records on file2 file", "mismatch count", len(mismatches))

	// check missing records between the file1 and file2 files
	file1Data, file2Data, m = checkMissing(file1Data, file2Data, key, file1Name, file2Name)
	mismatches = append(mismatches, m...)
	logger.Debug("checked for missing data between the files", "mismatch count", len(mismatches))

	// Compare the values in the data sets field by field
	m = fieldCompare(file1Data, file2Data, key)
	mismatches = append(mismatches, m...)

	buf := &bytes.Buffer{}
	writer := csv.NewWriter(buf)

	// Write header
	header := []string{key, "Field", file1Name, file2Name, "Error"}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write rows
	for _, m := range mismatches {
		row := []string{m.key, m.field, m.file1, m.file2, m.message}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	// Write remaining data to the buffer
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Compares every field of every record in each dataset and reports mismatches between the two.
func fieldCompare(file1, file2 []map[string]string, key string) []mismatch {
	var mismatches []mismatch

	// Get a slice of all the fields in the data sets
	fields := getFieldNames(file1[0])

	// Loop through every row in the data sets and compare each field
	for _, bRow := range file1 {
		aRow := findRow(file2, key, bRow[key])
		// Loop over each field to compare them between the rows
		for _, f := range fields {
			// Continue to the next field if they match
			if aRow[f] == bRow[f] {
				continue
			}

			// there is a mismatch
			m := mismatch{
				key:     bRow[key],
				field:   f,
				file1:   bRow[f],
				file2:   aRow[f],
				message: "data mismatch",
			}
			mismatches = append(mismatches, m)
		}
	}

	return mismatches
}

// Finds the row/record in a CSV data with a key matching a given value
func findRow(data []map[string]string, key, value string) map[string]string {
	for _, row := range data {
		if row[key] == value {
			return row
		}
	}

	return nil
}

// Checks for missing records between the two csv files. Any missing records are returned as mismatches.
func checkMissing(file1, file2 []map[string]string, key, file1Name, file2Name string) ([]map[string]string, []map[string]string, []mismatch) {
	var (
		mismatches []mismatch
		newfile1   []map[string]string
		newfile2   []map[string]string
	)

	// Check for file1 records missing in the file2 file
	keys := extractKeys(file2, key)
	for _, record := range file1 {
		// Continue if the file1 data key exists in the file2 data keys list
		if slices.Contains(keys, record[key]) {
			newfile1 = append(newfile1, record)
			continue
		}

		// This record is a mismatch
		mismatches = append(mismatches, mismatch{
			key:     record[key],
			field:   key,
			file1:   record[key],
			file2:   "missing",
			message: fmt.Sprintf("'%s' missing record with %s '%v'", file2Name, key, record[key]),
		})
	}

	// Check for file2 records missing in the file1 file
	keys = extractKeys(file1, key)
	for _, record := range file2 {
		// Continue if the file1 data key exists in the file2 data keys list
		if slices.Contains(keys, record[key]) {
			newfile2 = append(newfile2, record)
			continue
		}

		// This record is a mismatch
		mismatches = append(mismatches, mismatch{
			key:     record[key],
			field:   key,
			file1:   "missing",
			file2:   record[key],
			message: fmt.Sprintf("'%s' missing record with %s '%v'", file1Name, key, record[key]),
		})
	}

	return newfile1, newfile2, mismatches
}

// Extracts a list of the unique identifiers (keys) from a slice of maps
func extractKeys(data []map[string]string, key string) []string {
	// Make a slice to store all the keys
	keys := make([]string, len(data))

	// Loop through all the data records and add the key to the keys slice
	for i, record := range data {
		keys[i] = record[key]
	}

	return keys
}

// Remove duplicates identifies duplicate keys as mismatches.
// Returns CSV Data without the duplicates.
func deDuplicate(data []map[string]string, key, name string) ([]map[string]string, []mismatch) {
	var (
		result     []map[string]string
		mismatches []mismatch
	)
	seen := map[string]bool{}

	// Loop through the csv data
	for i, row := range data {
		value := row[key]
		// If the key value hasn't been seen file1, add it to the result.
		if !seen[value] {
			seen[value] = true
			result = append(result, row)
			continue
		}

		// The value has been seen file1, it's a "mismatch"
		m := mismatch{
			key:     value,
			field:   key,
			file1:   "n/a",
			file2:   "n/a",
			message: fmt.Sprintf("duplicate '%v' on '%v' at row %v", key, name, i+1),
		}
		mismatches = append(mismatches, m)

	}
	return result, mismatches
}

// normalizeColumns checks the columns to see if it has any columns (fields)
// that aren't in the slice of fields from the other file.
func normalizeColumns(data []map[string]string, fields []string, name string) ([]map[string]string, []mismatch) {
	var mismatches []mismatch
	dataFields := getFieldNames(data[0])

	// Make a list of any "extra" fields in the data that don't
	// have a value in the fields slice
	var extraFields []string
	for _, df := range dataFields {
		if !sliceContains(fields, df) {
			extraFields = append(extraFields, df)
		}
	}

	// If there aren't any extra fields, early return
	if len(extraFields) == 0 {
		return data, mismatches
	}

	// Remove all the items from the data maps that match
	// an extraField
	for i, row := range data {
		for _, f := range extraFields {
			delete(row, f)
			data[i] = row
		}
	}

	// Create a mismatch record for each of the extra fields
	for _, f := range extraFields {
		m := mismatch{
			key:     "n/a",
			field:   f,
			file1:   "n/a",
			file2:   "n/a",
			message: fmt.Sprintf("extra column '%v' on '%v' file", f, name),
		}
		mismatches = append(mismatches, m)
	}

	return data, mismatches
}

// Returns true if a slice contains a test value
func sliceContains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// Extracts the keys from a map
func getFieldNames(m map[string]string) []string {
	keys := make([]string, len(m))

	i := 0
	for k := range m {
		keys[i] = k
		i++
	}

	return keys
}

// Read a CSV file into a slice map
func csvFileToSliceMap(file io.Reader, key string) ([]map[string]string, error) {
	var (
		header []string
		data   []map[string]string
	)

	// Read the CSV file
	csvReader := csv.NewReader(file)

	// Loop through the file to find the header
	for i := 0; i >= 0; i++ {

		// Read the next line
		row, err := csvReader.Read()
		// Stop looping if it's the end of the file
		if errors.Is(err, io.EOF) {
			break
		}

		// Check to see if this row is the header based on the presence of the key field
		for _, field := range row {
			// Break out of the loop when the key field is found in the row
			if field == key {
				header = row
				break
			}
		}

		// Break out of the record loop if the header was found
		if len(header) > 0 {
			break
		}
	}

	// Check to make sure the header was found or return an error
	if len(header) == 0 {
		return data, fmt.Errorf("no header")
	}

	// Read through the remaining records to create the slice>map of data
	for i := 0; i >= 0; i++ {
		// Read the next line
		row, err := csvReader.Read()
		// Exit the loop if it's the end of the file
		if errors.Is(err, io.EOF) {
			break
		}

		// Loop through each
		record := make(map[string]string)
		for j, k := range header {
			record[k] = row[j]
		}

		// Append the row map to the data slice
		data = append(data, record)
	}

	return data, nil
}
