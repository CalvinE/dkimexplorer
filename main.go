package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"unicode"
	"unicode/utf8"
)

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
	SUCCESS  = "SUCCESS"
	TEMPFAIL = "TEMPFAIL"
	PERMFAIL = "PERMFAIL"
)

type DKIMValidationResult struct {
	DKIMHeader DKIMSignature       `json:"dkimSignatuer"`
	Result     DKIMValidationState `json:"validationResult"`
}

type inputArgs struct {
	inputEmailFile string
	verbose        bool
}

const (
	cr  = '\r'
	lf  = '\n'
	sp  = ' '
	tab = '\t'

	colon     = ':'
	semicolon = ";"
	equals    = "="

	CRLF = "\r\n"
)

var (
	parserState = Unset
)

func main() {
	var inputArgs inputArgs
	flag.StringVar(&inputArgs.inputEmailFile, "inputFile", "sample_email.txt", "The input email file for DKIM signature verification")
	flag.BoolVar(&inputArgs.verbose, "verbose", false, "if true additional information will be printed to stdout")
	flag.Parse()
	fileData, err := ioutil.ReadFile(inputArgs.inputEmailFile)
	if err != nil {
		fmt.Printf("failed to open file %s: %s", inputArgs.inputEmailFile, err.Error())
		os.Exit(1)
		return
	}
	fileLength := len(fileData)
	if fileLength <= 0 {
		fmt.Printf("file contains no data!%s", CRLF)
		os.Exit(2)
		return
	}
	if inputArgs.verbose {
		fmt.Printf("file length: %d%s", fileLength, CRLF)
	}
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
		fmt.Printf("%s%smessage body:%s%s%s%s", CRLF, CRLF, CRLF, CRLF, message.RawBody, CRLF)
	}

	// get DKIM Signature headers
	dkimSignatures := message.GetHeadersByName("dkim-signature")
	numDKIMSignatures := len(dkimSignatures)
	dkimSignatureValidtionResults := make([]DKIMValidationResult, 0, numDKIMSignatures)
	// we need to go backwards through the list of signatures because of how multiple headers are handeled per
	// https://datatracker.ietf.org/doc/html/rfc6376#section-5.4.2
	for i := numDKIMSignatures - 1; i >= 0; i-- {
		signature, err := ParseDKIMSignature(dkimSignatures[i])
		if err != nil {
			fmt.Printf("%s%sfailed to parse DKIM Signature with error: %s%s%s", CRLF, CRLF, err.Error(), CRLF, CRLF)
			fmt.Printf("due to failure of DKIM-Signature parseing the signature validate results is: PERFAIL%s%s", CRLF, CRLF)
			continue
		}
		fmt.Printf("%s%s--- STARTING DKIM SIGNATURE VALIDATION ---%s", CRLF, CRLF, CRLF)
		fmt.Printf("DKIM Signature #%d with domain %s and selector %s%s", i+1, signature.SigningDomainIdentifier, signature.Selector, CRLF)
		result, err := validateDKIMSignature(&message, signature, dkimSignatures[:i])
		if err != nil {
			fmt.Printf("FAILED DKIM SIGNATURE VALIDATION: %s%s", err.Error(), CRLF)
		}
		fmt.Printf("RESULT: %s%s", string(result), CRLF)
		fmt.Printf("--- END DKIM SIGNATURE VALIDATION ---%s%s", CRLF, CRLF)
		dkimSignatureValidtionResults = append(dkimSignatureValidtionResults, DKIMValidationResult{
			DKIMHeader: signature,
			Result:     result,
		})
	}
	// read body

	// summary info
	printSummary(&message, dkimSignatureValidtionResults)
}

func printSummary(message *message, dkimSignatureValidationResults []DKIMValidationResult) {

	fmt.Printf("%s%s---Message summary---%s", CRLF, CRLF, CRLF)

	fmt.Printf("%sMessage Details%s", CRLF, CRLF)
	fmt.Printf("\tBody length:\t%d%s", len(message.RawBody), CRLF)

	fmt.Printf("%sMessage header details%s", CRLF, CRLF)
	fmt.Printf("\tNumber of headers:\t%d%s", len(message.Headers), CRLF)
	numDkimSignatures := len(dkimSignatureValidationResults)
	for _, header := range message.Headers {
		normalizedHeaderKey := header.getHeaderKey(true)
		switch normalizedHeaderKey {
		case "content-type":
			fmt.Printf("\t%s:\t%s%s", normalizedHeaderKey, header.getHeaderTrimmedValue(), CRLF)
		case "to":
			fmt.Printf("\t%s:\t%s%s", normalizedHeaderKey, header.getHeaderTrimmedValue(), CRLF)
		case "from":
			fmt.Printf("\t%s:\t%s%s", normalizedHeaderKey, header.getHeaderTrimmedValue(), CRLF)
		case "subject":
			fmt.Printf("\t%s:\t%s%s", normalizedHeaderKey, header.getHeaderTrimmedValue(), CRLF)
		case "reply-to":
			fmt.Printf("\t%s:\t%s%s", normalizedHeaderKey, header.getHeaderTrimmedValue(), CRLF)
		}
	}

	fmt.Printf("%sDKIM Signature Validation Summary%s", CRLF, CRLF)
	validCount := 0
	for _, s := range dkimSignatureValidationResults {
		fmt.Printf("\tSignature %s:%s%s\t\tvalidation result: %s%s", s.DKIMHeader.SigningDomainIdentifier, s.DKIMHeader.Selector, CRLF, s.Result, CRLF)
		if s.Result == SUCCESS {
			validCount++
		}
	}
	fmt.Printf("\tValid DKIM Signatures:\t%d/%d%s", validCount, numDkimSignatures, CRLF)
}

func removeWhitespace(input []byte) string {
	inputLength := len(input)
	outputBytes := make([]byte, 0, len(input))
	for i := 0; i < inputLength; {
		currentRune, width := utf8.DecodeRune(input[i:])
		i += width
		if unicode.IsSpace(currentRune) {
			continue
		}
		outputBytes = append(outputBytes, byte(currentRune))
	}
	return string(outputBytes)
}
