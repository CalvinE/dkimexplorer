package main

import "strings"

type message struct {
	// header is a slice of Headers for the message. critically for SKIM signature validation they are in the same order they were encountered in the raw message data.
	Headers []header
	RawBody []byte
}

func (message *message) GetHeadersByName(name string) []header {
	var matchingHeaders []header
	normalizedName := strings.ToLower(name)
	for _, h := range message.Headers {
		if h.getHeaderKey(true) == normalizedName {
			matchingHeaders = append(matchingHeaders, h)
		}
	}
	return matchingHeaders
}
