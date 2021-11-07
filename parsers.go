package main

import (
	"strings"
	"unicode/utf8"
)

func parseKeyValuePairs(data []byte, seperator, terminator rune) map[string]string {
	parsedMap := make(map[string]string)
	currentRuneIndex := 0
	lastSemicolonIndex := 0
	lastEqualsIndex := 0
	rawValueLength := len(data)
	var key, value string
	for currentRuneIndex < rawValueLength {
		currentRune, width := utf8.DecodeRune(data[currentRuneIndex:])
		currentRuneIndex += width
		if currentRune == seperator && lastEqualsIndex == 0 {
			rawKey := string(data[lastSemicolonIndex : currentRuneIndex-width])
			key = strings.TrimSpace(rawKey)
			lastEqualsIndex = currentRuneIndex
		} else if currentRune == terminator {
			rawValue := string(data[lastEqualsIndex : currentRuneIndex-width])
			value = strings.TrimSpace(rawValue)
			lastSemicolonIndex = currentRuneIndex
			lastEqualsIndex = 0
			parsedMap[key] = value
			key, value = "", ""
		}
	}
	if lastEqualsIndex != 0 {
		// unterminated field in data
		rawValue := string(data[lastEqualsIndex:])
		value = strings.TrimSpace(rawValue)
		parsedMap[key] = value
	}
	return parsedMap
}
