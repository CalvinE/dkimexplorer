package main

import (
	"flag"
	"fmt"
	"io/ioutil"
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

	return TEMPFAIL
}
