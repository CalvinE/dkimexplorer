package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type CanonicalizationAlgorithm func(header) ([]byte, error)

// In hash step 1, the Signer/Verifier MUST hash the message body,
// canonicalized using the body canonicalization algorithm specified in
// the "c=" tag and then truncated to the length specified in the "l="
// tag.  That hash value is then converted to base64 form and inserted
// into (Signers) or compared to (Verifiers) the "bh=" tag of the DKIM-
// Signature header field.
func canonicalizeBody(message *message, canonicalizationAlogrithm DKIMCanonAlgorithm, length int) ([]byte, error) {
	switch canonicalizationAlogrithm {
	case DKIM_CANON_ALGO_SIMPLE, DKIM_CANON_ALGO_RELAXED_SIMPLE, DKIM_CANON_ALGO_SIMPLE_SIMPLE:
		// simple canonicalization algorithm
		return simpleCanonicalizeBody(message.RawBody, length)
	case DKIM_CANON_ALGO_RELAXED, DKIM_CANON_ALGO_RELAXED_RELAXED, DKIM_CANON_ALGO_SIMPLE_RELAXED:
		// relaxed canonicalization algorithm
		return relaxedCanonicalizeBody(message.RawBody, length)
	}
	return nil, fmt.Errorf("failed to canonicalize body with algorithm specifed: %s", canonicalizationAlogrithm.String())
}

// simpleCanonicalizeBody per https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.3 removed all empty lines from the end of the body,
// leaving only one CRLF at the end of the body.
func simpleCanonicalizeBody(messageBody []byte, length int) ([]byte, error) {
	messageBodyLength := len(messageBody)
	relevantBodyBytes := make([]byte, messageBodyLength)
	copiedBytes := copy(relevantBodyBytes, messageBody)
	currentBodyIndex := copiedBytes
	startTrailingCRLFStartIndex := messageBodyLength
	if messageBodyLength >= 2 {
		for currentBodyIndex >= 0 {
			previousByte := relevantBodyBytes[currentBodyIndex-2]
			currentByte := relevantBodyBytes[currentBodyIndex-1]
			currentBodyIndex -= 2
			if previousByte == '\r' && currentByte == '\n' {
				startTrailingCRLFStartIndex = currentBodyIndex
			} else {
				break
			}
		}
	}
	// add back
	relevantBodyBytes = append(relevantBodyBytes[:startTrailingCRLFStartIndex], '\r', '\n')
	if length == DEFAULT_BODY_LENGTH_LIMIT {
		length = len(relevantBodyBytes)
	}
	return relevantBodyBytes[:length], nil
}

func relaxedCanonicalizeBody(messageBody []byte, length int) ([]byte, error) {
	currentBodyIndex := 0
	messageLength := len(messageBody)
	relaxedBodyBytes := make([]byte, 0, messageLength)
	consecutiveSpaceCharacters := 0
	// startSpaceIndex, consecutiveSpaceCharacters := 0, 0
	var previousRune rune
	for currentBodyIndex < messageLength {
		currentRune, width := utf8.DecodeRune(messageBody[currentBodyIndex:])
		currentBodyIndex += width
		if unicode.IsSpace(currentRune) {
			consecutiveSpaceCharacters++
			if previousRune == '\r' && currentRune == '\n' {
				// next is new line
				relaxedBodyBytes = append(relaxedBodyBytes, '\r', '\n')
				consecutiveSpaceCharacters = 0
			}
			// is not new line
		} else {
			if consecutiveSpaceCharacters > 0 {
				relaxedBodyBytes = append(relaxedBodyBytes, byte(' '), byte(currentRune))
				consecutiveSpaceCharacters = 0
			} else {
				relaxedBodyBytes = append(relaxedBodyBytes, byte(currentRune))
			}
		}

		previousRune = currentRune
	}
	// TODO: I think this can be improved, but for times sake I just use this code. The last step of the relaxed body canonicalization method is to basically run the
	relaxedBodyBytes, err := simpleCanonicalizeBody(relaxedBodyBytes, length)
	if err != nil {
		return nil, err
	}
	if length == DEFAULT_BODY_LENGTH_LIMIT {
		length = len(relaxedBodyBytes)
	}
	return relaxedBodyBytes[:length], nil
}

func canonicalizeHeaders(message *message, canonicalizationAlogrithm DKIMCanonAlgorithm, otherDKIMSignatures []header, headers []string) ([]byte, error) {
	var canonFunc CanonicalizationAlgorithm
	canonicalizedHeadersData := make([]byte, 0)
	switch canonicalizationAlogrithm {
	case DKIM_CANON_ALGO_SIMPLE, DKIM_CANON_ALGO_SIMPLE_RELAXED, DKIM_CANON_ALGO_SIMPLE_SIMPLE:
		// simple canonicalization algorithm
		canonFunc = simpleCanonicalizeHeaders
	case DKIM_CANON_ALGO_RELAXED, DKIM_CANON_ALGO_RELAXED_RELAXED, DKIM_CANON_ALGO_RELAXED_SIMPLE:
		// relaxed canonicalization algorithm
		canonFunc = relaxedCanonicalizeHeaders
	}
	headerOccurences := make(map[string]int)
	for _, h := range headers {
		normalizedHeaderName := strings.ToLower(strings.TrimSpace(h))
		occurences := headerOccurences[normalizedHeaderName]
		var headerPool []header
		if normalizedHeaderName == DKIMSignatureHeaderName {
			// the DKIM SIgnature is a special case for signing
			headerPool = otherDKIMSignatures
		} else {
			headerPool = message.Headers
		}
		nextHeader, ok := getNextHeader(h, occurences, headerPool)
		if ok {
			canonacalizedHeaderBytes, err := canonFunc(nextHeader)
			if err != nil {
				err = fmt.Errorf("failed to canonicalize header %s occrence %d with %s algorithm", h, 0, canonicalizationAlogrithm.String())
				return nil, err
			}
			canonicalizedHeadersData = append(canonicalizedHeadersData, canonacalizedHeaderBytes...)
		}
		headerOccurences[normalizedHeaderName] = occurences + 1
	}
	return canonicalizedHeadersData, nil
}

// looking for next non signed header per https://datatracker.ietf.org/doc/html/rfc6376#section-5.4.2
func getNextHeader(headerName string, PreviousHeaderCount int, headers []header) (header, bool) {
	loweredTrimmerHeaderName := strings.ToLower(strings.TrimSpace(headerName))
	occurrences := 0
	numHeaders := len(headers)
	for i := numHeaders - 1; i >= 0; i-- {
		currentHeader := headers[i].getHeaderKey(true)
		if currentHeader == loweredTrimmerHeaderName {
			if PreviousHeaderCount == occurrences {
				// we found the next header
				return headers[i], true
			}
			occurrences++
		}
	}
	// Per https://datatracker.ietf.org/doc/html/rfc6376#section-3.5 - specifically the definition of the 'h=' field of the DKIM-Signature
	/*
		 	"The field MAY contain names of header
			fields that do not exist when signed; nonexistent header fields do
			not contribute to the signature computation (that is, they are
			treated as the null input, including the header field name, the
			separating colon, the header field value, and any CRLF
			terminator)."
	*/

	// constructedHeaderBytes := fmt.Sprintf("%s:\r\n", loweredTrimmerHeaderName)
	return header{
		// RawHeaderBytes: []byte(constructedHeaderBytes),
	}, false
}

func canonicalizeHeaderBytes(headerBytes []byte, canonicalizationAlogrithm DKIMCanonAlgorithm) ([]byte, error) {
	header := header{
		RawHeaderBytes: make([]byte, len(headerBytes)),
	}
	copy(header.RawHeaderBytes, headerBytes)
	switch canonicalizationAlogrithm {
	case DKIM_CANON_ALGO_SIMPLE, DKIM_CANON_ALGO_SIMPLE_RELAXED, DKIM_CANON_ALGO_SIMPLE_SIMPLE:
		// simple canonicalization algorithm
		return simpleCanonicalizeHeaders(header)
	case DKIM_CANON_ALGO_RELAXED, DKIM_CANON_ALGO_RELAXED_RELAXED, DKIM_CANON_ALGO_RELAXED_SIMPLE:
		// relaxed canonicalization algorithm
		return relaxedCanonicalizeHeaders(header)
	}
	return nil, fmt.Errorf("canonicalization algorithm provided is invalid: %s", canonicalizationAlogrithm)
}

// per https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.1
func simpleCanonicalizeHeaders(header header) ([]byte, error) {
	return header.RawHeaderBytes, nil
}

// per https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.2
func relaxedCanonicalizeHeaders(header header) ([]byte, error) {
	// convert header name to lowercase
	loweredTrimmedHeaderName := header.getHeaderKey(true)
	rawHeaderValueBytes := header.getHeaderRawValueBytes()
	rawHeaderValueLength := len(rawHeaderValueBytes)
	canonicalizedData := make([]byte, 0, len(header.RawHeaderBytes))
	// remove any space before colon seperator
	canonicalizedStart := fmt.Sprintf("%s:", loweredTrimmedHeaderName)
	canonicalizedData = append(canonicalizedData, canonicalizedStart...)
	currentIndex, consecutiveWhitespace := 0, 0

	// clean up whitespace between colon and value
	for currentIndex < rawHeaderValueLength {
		currentRune, width := utf8.DecodeRune(rawHeaderValueBytes[currentIndex:])
		if !unicode.IsSpace(currentRune) {
			// on first non space character break and start whitespace clean up loop.
			break
		}
		currentIndex += width
	}
	for currentIndex < rawHeaderValueLength {
		currentRune, width := utf8.DecodeRune(rawHeaderValueBytes[currentIndex:])
		currentIndex += width
		if unicode.IsSpace(currentRune) {
			consecutiveWhitespace++
		} else if consecutiveWhitespace > 0 {
			canonicalizedData = append(canonicalizedData, ' ', byte(currentRune))
			consecutiveWhitespace = 0
		} else {
			canonicalizedData = append(canonicalizedData, byte(currentRune))
		}
	}
	// add ending CRLF
	canonicalizedData = append(canonicalizedData, '\r', '\n')
	return canonicalizedData, nil
}
