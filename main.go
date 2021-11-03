package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"unicode"
	"unicode/utf8"
)

type inputArgs struct {
	inputEmailFile string
	verbose        bool
}

type ParserState uint8

const (
	Unset ParserState = iota

	PreHeaders
	HeaderKey
	HeaderValue
	EndHeader
	PostHeaders

	PreBody
	InBody
	EndBody
	PostBody
)

type DKIMValidationState string

const (
	VALID    = "VALID"
	TEMPFAIL = "TEMPFAIL"
	PERMFAIL = "PERMFAIL"
)

const (
	cr  = '\r'
	lf  = '\n'
	sp  = ' '
	tab = '\t'

	colon     = ':'
	semicolon = ";"
	equals    = "="
)

var (
	parserState = Unset
)

func main() {
	var inputArgs inputArgs
	flag.StringVar(&inputArgs.inputEmailFile, "inputFile", "sample_email.txt", "The input email file for DKIM signature verification")
	flag.BoolVar(&inputArgs.verbose, "verbose", true, "if true additional information will be printed to stdout")
	flag.Parse()
	fileData, err := ioutil.ReadFile(inputArgs.inputEmailFile)
	if err != nil {
		fmt.Printf("failed to open file %s: %s", inputArgs.inputEmailFile, err.Error())
		os.Exit(1)
		return
	}
	fileLength := len(fileData)
	if fileLength <= 0 {
		fmt.Print("file contains no data!\n")
		os.Exit(2)
		return
	}
	fmt.Printf("file length: %d\n", fileLength)
	message := message{}
	parserState = HeaderKey
	var currentFileIndex int
	// parse headers

	// currentLineIndex helps us keep track of how many characters in a header we are
	var currentHeaderIndex uint = 0
	currentHeader := &header{}
	var previousRune rune
	for currentFileIndex < fileLength {
		// decode text as UTF-8 to handle a wide variety of characters in text?
		currentRune, width := utf8.DecodeRune(fileData[currentFileIndex:])
		currentFileIndex += width
		currentHeaderIndex += uint(width)
		if currentRune == lf {
			// we hit a line feed.
			if previousRune == cr && currentFileIndex < fileLength {
				// we are not at the end of the file and the previous rune was a CR.
				if currentHeaderIndex == 2 {
					// end of headers... Designated by an empty line
					parserState = PostHeaders
					break
				}
				// the preivous character was a carrage return!
				nextRune, width2 := utf8.DecodeRune(fileData[currentFileIndex:])
				isNextRuneWhiteSpace := unicode.IsSpace(nextRune)
				// making sure that if the next character is whitespace that it s not CR or LF because that does not count for folding whitespace
				if isNextRuneWhiteSpace && nextRune != cr && nextRune != lf {
					// current index is part of folding white space
					// because the first character on the next line is white space.
					// we want to capture the index of the folding whitespace CR
					// so we can quickly get to it later.
					currentHeader.FoldingWhiteSpaceRelativeStartIndexes = append(currentHeader.FoldingWhiteSpaceRelativeStartIndexes, currentHeaderIndex)
					currentHeaderIndex += uint(width2)
				} else {
					// This is not folding white space, so it must be a new header!
					// current index is end of header
					currentHeader.AbsoluteEndIndex = uint(currentFileIndex)
					currentHeader.RawHeaderBytes = make([]byte, currentHeaderIndex)
					currentHeader.HeaderLength = currentHeaderIndex
					// copying all header bytes into byte slice in the header struct
					// so we can play with it later.
					// I made a symantic choice here. the way slicing works here is the number
					// after the : is like saying up to but not including that item
					// I may come back and change this so that the end index in the slicing below
					// adds one to the end index and makes this value the actual end of the header,
					// but I think I am over thinking it so I will leave it be for now. for our
					// purposes it works fine...
					_ = copy(currentHeader.RawHeaderBytes, fileData[currentHeader.AbsoluteStartIndex:currentHeader.AbsoluteEndIndex])
					// fmt.Printf("%d copied \n", copied)
					// fmt.Printf("key=%s\nvalue=%s\n\n", currentHeader.getHeaderKey(true), currentHeader.getHeaderRawValue())
					message.Headers = append(message.Headers, *currentHeader)
					currentHeader = &header{
						AbsoluteStartIndex: uint(currentFileIndex),
					}
					currentHeaderIndex = uint(1)
					parserState = HeaderKey
				}
				// increment out file position index and our previous run since we skipped one ahead
				currentFileIndex += width2
				previousRune = nextRune
				continue
			} else {
				// end of file?
				fmt.Println("Encountered end of file while parsing headers???")
				os.Exit(3)
				break
			}
		} else if currentRune == colon && parserState == HeaderKey {
			currentHeader.RelativeSeperatorIndex = currentHeaderIndex - uint(width)
			parserState = HeaderValue
		}
		previousRune = currentRune
	}

	if inputArgs.verbose {
		for i, header := range message.Headers {
			fmt.Printf("%d:\tkey = %s\t value = %s", i+1, header.getHeaderKey(false), header.getHeaderRawValueString())
		}
	}

	parserState = InBody
	remainingLength := fileLength - currentFileIndex
	message.RawBody = make([]byte, remainingLength)
	copy(message.RawBody, fileData[currentFileIndex:])
	parserState = PostBody
	if inputArgs.verbose {
		fmt.Printf("\n\nmessage body:\n\n%s", message.RawBody)
	}

	// get DKIM Signature headers
	dkimSignatures := message.GetHeadersByName("dkim-signature")
	// we need to go backwards through the list of signatures because of how multiple headers are handeled per
	// https://datatracker.ietf.org/doc/html/rfc6376#section-5.4.2
	for i := len(dkimSignatures) - 1; i >= 0; i-- {
		signature, err := ParseDKIMSignature(dkimSignatures[i])
		if err != nil {
			fmt.Printf("\n\nfailed to parse DKIM Signature with error: %s\n\n", err.Error())
			os.Exit(4)
		}
		result := validateDKIMSignature(&message, signature, dkimSignatures[:i])
		fmt.Printf("DKIM Signature %d result: %s\n", i, string(result))
	}
	// read body

	// summary info
	printSummary(&message)
}

func printSummary(message *message) {

	fmt.Print("\n\n---Message summary---\n")
	fmt.Printf("Number of headers:\t%d\n", len(message.Headers))
	numDkimSignatures := 0
	for _, header := range message.Headers {
		normalizedHeaderKey := header.getHeaderKey(true)
		switch normalizedHeaderKey {
		case "content-type":
			fmt.Printf("%s:\t%s\n", header.getHeaderKey(true), header.getHeaderTrimmedValue())
		case "to":
			fmt.Printf("%s:\t%s\n", header.getHeaderKey(true), header.getHeaderTrimmedValue())
		case "from":
			fmt.Printf("%s:\t%s\n", header.getHeaderKey(true), header.getHeaderTrimmedValue())
		case "subject":
			fmt.Printf("%s:\t%s\n", header.getHeaderKey(true), header.getHeaderTrimmedValue())
		case "reply-to":
			fmt.Printf("%s:\t%s\n", header.getHeaderKey(true), header.getHeaderTrimmedValue())
		case "dkim-signature":
			numDkimSignatures++
		}
	}
	fmt.Printf("Number of DKIM Signatures:\t%d\n", numDkimSignatures)
	fmt.Printf("Body length:\t%d\n", len(message.RawBody))
}

func validateDKIMSignature(message *message, dkimSignatureToValidate DKIMSignature, otherDKIMSignatures []header) DKIMValidationState {
	// calculate canonicalized body
	canonicalizeBodyBytes, err := canonicalizeBody(message, dkimSignatureToValidate.CanonicalizationAlgorithm, dkimSignatureToValidate.BodyLengthLimit)
	if err != nil {
		fmt.Printf("Failed to canonicalize body of message: %s\n\n", err.Error())
		return PERMFAIL
	}
	// calculate hash on canonicalized body hash
	var canonicalizedBodyHash string
	switch dkimSignatureToValidate.Algorithm {
	case DKIM_ALGORITHM_RSA_SHA_1:
		hash := sha1.Sum(canonicalizeBodyBytes)
		canonicalizedBodyHash = base64.StdEncoding.EncodeToString(hash[:])
	case DKIM_ALGORITHM_RSA_SHA_256:
		hash := sha256.Sum256(canonicalizeBodyBytes)
		canonicalizedBodyHash = base64.StdEncoding.EncodeToString(hash[:])
	}
	// confirm canonicalized body hash to dkim signature bh value
	if canonicalizedBodyHash != dkimSignatureToValidate.BodySignature {
		fmt.Printf("body hash does not match: got: %s - expected: %s\n\n", canonicalizedBodyHash, dkimSignatureToValidate.BodySignature)
		return PERMFAIL
	}
	// caluclate canonicalize headers
	// TODO:

	// get "domain key" from set query method
	// for now I am going to assume the value is the defaul which is "dns/txt" I dont know if ill implment others...
	if dkimSignatureToValidate.QueryMethod != DEFAULT_QUERY_METHOD {
		fmt.Println("currently only one query method is supported.")
		fmt.Printf("unsupported query method encountered: got: %s - expected: %s\n\n", dkimSignatureToValidate.QueryMethod, DEFAULT_QUERY_METHOD)
		return TEMPFAIL
	}
	domainKeyLocation := fmt.Sprintf("%s._domainkey.%s", dkimSignatureToValidate.Selector, dkimSignatureToValidate.SigningDomainIdentifier)
	records, err := net.LookupTXT(domainKeyLocation)
	if err != nil {
		fmt.Printf("failed to retreive domain key from location %s: %s\n\n", domainKeyLocation, err.Error())
	}
	numRecords := len(records)
	if numRecords != 1 {
		fmt.Printf("no txt record or more than one txt record found. numtxt records: %d\n\n", numRecords)
		return TEMPFAIL
	}
	// parse domain key from record return from query method
	domainKey, err := ParseDomainKey([]byte(records[0]))
	if err != nil {
		fmt.Printf("failed to parse domain key: %s\n\n", err.Error())
		return TEMPFAIL
	}
	fmt.Println(domainKey)
	fmt.Println(canonicalizedBodyHash)
	// check for y flag and return TEMPFAIL is present. Per https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1
	if domainKey.Flags.ContainsFlag(DomainKeyFlag_Y) {
		fmt.Print("failing signature validation because y flag is present in domain key\n\n")
		return TEMPFAIL
	}
	return TEMPFAIL
}

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
	if length == DEFAULT_BODY_LENGTH_LIMIT {
		length = len(relaxedBodyBytes)
	}
	return relaxedBodyBytes[:length], err
}
