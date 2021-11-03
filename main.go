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
	"strings"
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
			fmt.Print("due to failure of DKIM-Signature parseing the signature validate results is: PERFAIL\n\n")
			continue
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
	var canonicalizedBodyHash []byte
	var canonicalizedBodyHashBase64 string
	switch dkimSignatureToValidate.Algorithm {
	case DKIM_ALGORITHM_RSA_SHA_1:
		hash := sha1.Sum(canonicalizeBodyBytes)
		canonicalizedBodyHash = hash[:]
		canonicalizedBodyHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	case DKIM_ALGORITHM_RSA_SHA_256:
		hash := sha256.Sum256(canonicalizeBodyBytes)
		canonicalizedBodyHash = hash[:]
		canonicalizedBodyHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	}
	// confirm canonicalized body hash to dkim signature bh value
	if canonicalizedBodyHashBase64 != dkimSignatureToValidate.BodySignature {
		fmt.Printf("body hash does not match: got: %s - expected: %s\n\n", canonicalizedBodyHashBase64, dkimSignatureToValidate.BodySignature)
		return PERMFAIL
	}
	// caluclate canonicalize headers
	// TODO:
	canonicalizedHeaderData, err := canonicalizeHeaders(message, dkimSignatureToValidate.CanonicalizationAlgorithm, otherDKIMSignatures, dkimSignatureToValidate.SignedHeaders)
	if err != nil {
		fmt.Printf("failed to canonicalize headers: %s\n\n", err.Error())
		return TEMPFAIL
	}
	fmt.Println(string(canonicalizedHeaderData))
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
	if numRecords == 0 {
		// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #3
		fmt.Print("no txt record exists\n\n")
		return PERMFAIL
	}
	// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #4 we are opting to only try the first record.
	// the RFC leaves it to the implementers discression

	// parse domain key from record return from query method
	domainKey, err := ParseDomainKey([]byte(records[0]))
	if err != nil {
		// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #5
		fmt.Printf("failed to parse domain key: %s\n\n", err.Error())
		return PERMFAIL
	}
	// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item # 6
	// TODO: finish verifier steps...
	// check for y flag and return TEMPFAIL if it is present. Per https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1
	if domainKey.Flags.ContainsFlag(DomainKeyFlag_Y) {
		fmt.Print("failing signature validation because y flag is present in domain key\n\n")
		return TEMPFAIL
	}
	// https://datatracker.ietf.org/doc/html/rfc5451 looks like the value of i= for the DKIM-Signatures is stored over there...
	if domainKey.Flags.ContainsFlag(DomainKeyFlag_S) {
		// perform S flag validation.
		if len(dkimSignatureToValidate.AgentUserIdentifier) > 0 {
			domainPortionOfAUID := strings.Split(dkimSignatureToValidate.AgentUserIdentifier, "@")
			if len(domainPortionOfAUID) < 2 || domainPortionOfAUID[1] != dkimSignatureToValidate.SigningDomainIdentifier {
				fmt.Printf("AUID doamin %s does not match %s\n\n", domainPortionOfAUID[1], dkimSignatureToValidate.SigningDomainIdentifier)
				return PERMFAIL
			}
		} else {
			// per https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1
			/*
				s  Any DKIM-Signature header fields using the "i=" tag MUST have
				         the same domain value on the right-hand side of the "@" in the
				         "i=" tag and the value of the "d=" tag.  That is, the "i="
				         domain MUST NOT be a subdomain of "d=".  Use of this flag is
				         RECOMMENDED unless subdomaining is required.
			*/
			// from reading the RFC I am not sure if we should extract the i field from the Authentication-Results header
			// https://datatracker.ietf.org/doc/html/rfc5451 Authentication-Results header
			fmt.Print("skipping S flag AUID Signing DOmain verification because i= flag is not populated on DKIM signature\n\n")
		}
	}
	dkimSigForVerification := dkimSignatureToValidate.GetDKIMSignatureForVerificationOrSigning()
	canonicalizedDKIMSignature, err := canonicalizeHeaderBytes(dkimSigForVerification, dkimSignatureToValidate.CanonicalizationAlgorithm)
	fmt.Print(string(canonicalizedDKIMSignature))
	if err != nil {
		fmt.Printf("failed to canonicalize dkim signature for verification: %s\n\n", err.Error())
	}
	var signatureHash []byte
	var signatureHashBase64 string
	switch dkimSignatureToValidate.Algorithm {
	case DKIM_ALGORITHM_RSA_SHA_1:
		hashAlg := sha1.New()
		hashAlg.Write(canonicalizedHeaderData)
		hashAlg.Write(canonicalizedDKIMSignature)
		hash := hashAlg.Sum(canonicalizedBodyHash)
		signatureHash = hash[:]
		signatureHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	case DKIM_ALGORITHM_RSA_SHA_256:
		hashAlg := sha256.New()
		hashAlg.Write(canonicalizedHeaderData)
		hashAlg.Write(canonicalizedDKIMSignature)
		hash := hashAlg.Sum(canonicalizedBodyHash)
		signatureHash = hash[:]
		signatureHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	}
	fmt.Println(signatureHash)
	fmt.Println(signatureHashBase64)
	return TEMPFAIL
}

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
