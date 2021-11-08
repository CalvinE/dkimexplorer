package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

type DKIMVersion int

const (
	DKIM_VERSION_INVALID DKIMVersion = iota
	DKIM_VERSION_1
)

func (v DKIMVersion) String() string {
	switch v {
	case DKIM_VERSION_1:
		return "1"
	default:
		return "INVALID"
	}
}

func DKIMVersionValue(s string) DKIMVersion {
	versionString := strings.ToLower(strings.TrimSpace(s))
	switch versionString {
	case "1":
		return DKIM_VERSION_1
	default:
		return DKIM_VERSION_INVALID
	}
}

type DKIMAlgorithm int

const (
	DKIM_ALGORITHM_INVALID     DKIMAlgorithm = iota
	DKIM_ALGORITHM_RSA_SHA_1                 // "rsa-sha1"
	DKIM_ALGORITHM_RSA_SHA_256               //"rsa-sha256"
)

func (v DKIMAlgorithm) String() string {
	switch v {
	case DKIM_ALGORITHM_RSA_SHA_1:
		return "rsa-sha1"
	case DKIM_ALGORITHM_RSA_SHA_256:
		return "rsa-sha256"
	default:
		return "INVALID"
	}
}

func DKIMAlgorithmValue(s string) DKIMAlgorithm {
	algoString := strings.ToLower(strings.TrimSpace(s))
	switch algoString {
	case "rsa-sha1":
		return DKIM_ALGORITHM_RSA_SHA_1
	case "rsa-sha256":
		return DKIM_ALGORITHM_RSA_SHA_256
	default:
		return DKIM_ALGORITHM_INVALID
	}
}

type DKIMCanonAlgorithm int

const (
	DKIM_CANON_ALGO_INVALID         DKIMCanonAlgorithm = iota
	DKIM_CANON_ALGO_SIMPLE                             //"simple"
	DKIM_CANON_ALGO_SIMPLE_SIMPLE                      //"simple/simple"
	DKIM_CANON_ALGO_RELAXED                            //"relaxed"
	DKIM_CANON_ALGO_RELAXED_RELAXED                    //"relaxed/relaxed"
	DKIM_CANON_ALGO_RELAXED_SIMPLE                     //"relaxed/simple"
	DKIM_CANON_ALGO_SIMPLE_RELAXED                     //"simple/relaxed"
)

func (v DKIMCanonAlgorithm) String() string {
	switch v {
	case DKIM_CANON_ALGO_SIMPLE:
		return "simple"
	case DKIM_CANON_ALGO_SIMPLE_SIMPLE:
		return "simple/simple"
	case DKIM_CANON_ALGO_RELAXED:
		return "relaxed"
	case DKIM_CANON_ALGO_RELAXED_RELAXED:
		return "relaxed/relaxed"
	case DKIM_CANON_ALGO_RELAXED_SIMPLE:
		return "relaxed/simple"
	case DKIM_CANON_ALGO_SIMPLE_RELAXED:
		return "simple/relaxed"
	default:
		return "INVALID"
	}
}

func DKIMCanonAlgoValue(s string) DKIMCanonAlgorithm {
	canonAlgo := strings.ToLower(strings.TrimSpace(s))
	switch canonAlgo {
	case "simple":
		return DKIM_CANON_ALGO_SIMPLE
	case "simple/simple":
		return DKIM_CANON_ALGO_SIMPLE_SIMPLE
	case "relaxed":
		return DKIM_CANON_ALGO_RELAXED
	case "relaxed/relaxed":
		return DKIM_CANON_ALGO_RELAXED_RELAXED
	case "relaxed/simple":
		return DKIM_CANON_ALGO_RELAXED_SIMPLE
	case "simple/relaxed":
		return DKIM_CANON_ALGO_SIMPLE_RELAXED
	default:
		return DKIM_CANON_ALGO_INVALID
	}
}

const (
	DKIMSignatureHeaderName = "dkim-signature"

	// DEFAULT_BODY_LENGTH_LIMIT means there is no limit and the whole body should be use in signature validation
	DEFAULT_BODY_LENGTH_LIMIT = -1

	DEFAULT_QUERY_METHOD = "dns/txt"

	DKIMSignature_VersionKey                   = "v"
	DKIMSignature_AlgorithmKey                 = "a"
	DKIMSignature_SignatureKey                 = "b"
	DKIMSignature_BodySignatureKey             = "bh"
	DKIMSignature_CanonicalizationAlgorithmKey = "c"
	DKIMSignature_SigningDomainIdentifierKey   = "d"
	DKIMSignature_SignedHeadersKey             = "h"
	DKIMSignature_AgentUserIdentifierKey       = "i"
	DKIMSignature_BodyLengthLimitKey           = "l"
	DKIMSignature_QueryMethodKey               = "q"
	DKIMSignature_SelectorKey                  = "s"
	DKIMSignature_SignatureTimestampKey        = "t"
	DKIMSignature_SignatureExpirationKey       = "x"
	DKIMSignature_CopiedHeaderFieldsKey        = "z"
)

type DKIMSignature struct {
	Header                    header
	RawBytes                  []byte
	Version                   DKIMVersion        `json:"v"`
	Algorithm                 DKIMAlgorithm      `json:"a"`
	Signature                 string             `json:"b"`
	BodySignature             string             `json:"bh"`
	CanonicalizationAlgorithm DKIMCanonAlgorithm `json:"c"`
	SigningDomainIdentifier   string             `json:"d"`
	SignedHeaders             []string           `json:"h"`
	AgentUserIdentifier       string             `json:"i"`
	BodyLengthLimit           int                `json:"l"`
	QueryMethod               string             `json:"q"`
	Selector                  string             `json:"s"`
	SignatureTimestamp        string             `json:"t"`
	SignatureExpiration       string             `json:"x"`
	CopiedHeaderFields        string             `json:"z"`
}

// NewDKIMSignature is the proper way for creating a new DKIMSignature, and populates defaults.
func NewDKIMSignature() DKIMSignature {
	return DKIMSignature{
		CanonicalizationAlgorithm: DKIM_CANON_ALGO_SIMPLE,
		BodyLengthLimit:           DEFAULT_BODY_LENGTH_LIMIT,
		QueryMethod:               DEFAULT_QUERY_METHOD,
	}
}

func ParseDKIMSignature(header header) (DKIMSignature, error) {
	dkimSignature := NewDKIMSignature()
	dkimSignature.Header = header
	dkimSignature.RawBytes = header.RawHeaderBytes
	headerName := header.getHeaderKey(true)
	if headerName != DKIMSignatureHeaderName {
		return dkimSignature, fmt.Errorf("header name is not what was expected:\ngot -\t%s\n expected -\t%s", headerName, DKIMSignatureHeaderName)
	}
	rawHeaderValue := header.getHeaderRawValueBytes()
	dkimSignatureMap := parseKeyValuePairs(rawHeaderValue, '=', ';')
	for key, value := range dkimSignatureMap {
		dkimSignature.AddValue(key, value)
	}
	return dkimSignature, nil
}

func (sig *DKIMSignature) AddValue(key, value string) error {
	switch key {
	case DKIMSignature_VersionKey:
		val := removeWhitespace([]byte(value))
		sig.Version = DKIMVersionValue(val)
		if sig.Version != DKIM_VERSION_1 {
			return fmt.Errorf("the only permitted value of DKIM signature is 1: got - %d", sig.Version)
		}
	case DKIMSignature_AlgorithmKey:
		sig.Algorithm = DKIMAlgorithmValue(removeWhitespace([]byte(value)))
		if sig.Algorithm == DKIM_ALGORITHM_INVALID {
			return fmt.Errorf("unsupported DKIM signing algorithm specified: %s", value)
		}
	case DKIMSignature_SignatureKey:
		sig.Signature = removeWhitespace([]byte(value))
	case DKIMSignature_BodySignatureKey:
		sig.BodySignature = removeWhitespace([]byte(value))
	case DKIMSignature_CanonicalizationAlgorithmKey:
		sig.CanonicalizationAlgorithm = DKIMCanonAlgoValue(value)
		if sig.CanonicalizationAlgorithm == DKIM_CANON_ALGO_INVALID {
			return fmt.Errorf("unsupported canonicalization algorithm specified: %s", value)
		}
	case DKIMSignature_SigningDomainIdentifierKey:
		sig.SigningDomainIdentifier = removeWhitespace([]byte(value))
	case DKIMSignature_SignedHeadersKey:
		headers := strings.Split(value, ":")
		sig.SignedHeaders = headers
	case DKIMSignature_AgentUserIdentifierKey:
		sig.AgentUserIdentifier = removeWhitespace([]byte(value))
	case DKIMSignature_BodyLengthLimitKey:
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return err
		}
		sig.BodyLengthLimit = int(val)
	case DKIMSignature_QueryMethodKey:
		sig.QueryMethod = removeWhitespace([]byte(value))
	case DKIMSignature_SelectorKey:
		sig.Selector = removeWhitespace([]byte(value))
	case DKIMSignature_SignatureTimestampKey:
		sig.SignatureTimestamp = removeWhitespace([]byte(value))
	case DKIMSignature_SignatureExpirationKey:
		sig.SignatureExpiration = removeWhitespace([]byte(value))
	case DKIMSignature_CopiedHeaderFieldsKey:
		sig.CopiedHeaderFields = removeWhitespace([]byte(value))
	}
	return nil
}

// per https://datatracker.ietf.org/doc/html/rfc6376#section-3.7 item #2
func (dsig *DKIMSignature) GetDKIMSignatureForVerificationOrSigning() []byte {
	rawLength := len(dsig.Header.RawHeaderBytes)
	prepedDKIMSIgnature := make([]byte, 0, rawLength)
	isInB := false
	var previousRune rune
	for i := 0; i < rawLength; {
		currentRune, width := utf8.DecodeRune(dsig.RawBytes[i:])
		i += width
		if previousRune == 'b' && currentRune == '=' {
			// we are at the b field value of the dkim signature
			// lets skip until the semi colon if there is one.
			isInB = true
		} else if isInB {
			if currentRune != ';' {
				previousRune = currentRune
				continue
			}
			isInB = false
			// we want to preserve the semicolon? I am not 100% sure about this...
		}
		prepedDKIMSIgnature = append(prepedDKIMSIgnature, byte(currentRune))
		previousRune = currentRune
	}
	return prepedDKIMSIgnature
}

func GetDKIMSignatureForVerificationOrSigningBytes(sigBytes []byte) []byte {
	rawLength := len(sigBytes)
	prepedDKIMSIgnature := make([]byte, 0, rawLength)
	isInB := false
	var previousRune rune
	for i := 0; i < rawLength; {
		currentRune, width := utf8.DecodeRune(sigBytes[i:])
		i += width
		if previousRune == 'b' && currentRune == '=' {
			// we are at the b field value of the dkim signature
			// lets skip until the semi colon if there is one.
			isInB = true
		} else if isInB {
			if currentRune != ';' {
				previousRune = currentRune
				continue
			}
			isInB = false
			// we want to preserve the semicolon? I am not 100% sure about this...
		}
		prepedDKIMSIgnature = append(prepedDKIMSIgnature, byte(currentRune))
		previousRune = currentRune
	}
	// TODO: whi is the CRLF gone?
	return prepedDKIMSIgnature
}

func validateDKIMSignature(message *message, dkimSignatureToValidate DKIMSignature, otherDKIMSignatures []header) (DKIMValidationState, error) {
	// calculate canonicalized body
	canonicalizeBodyBytes, err := canonicalizeBody(message, dkimSignatureToValidate.CanonicalizationAlgorithm, dkimSignatureToValidate.BodyLengthLimit)
	if err != nil {
		fmt.Printf("Failed to canonicalize body of message: %s%s%s", err.Error(), CRLF, CRLF)
		return PERMFAIL, err
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
		fmt.Printf("body hash does not match: got: %s - expected: %s%s%s", canonicalizedBodyHashBase64, dkimSignatureToValidate.BodySignature, CRLF, CRLF)
		return PERMFAIL, errors.New("body hash does not validate")
	}
	// caluclate canonicalize headers
	canonicalizedHeaderData, err := canonicalizeHeaders(message, dkimSignatureToValidate.CanonicalizationAlgorithm, otherDKIMSignatures, dkimSignatureToValidate.SignedHeaders)
	if err != nil {
		fmt.Printf("failed to canonicalize headers: %s%s%s", err.Error(), CRLF, CRLF)
		return TEMPFAIL, err
	}
	// get "domain key" from set query method
	// for now I am going to assume the value is the defaul which is "dns/txt" I dont know if ill implment others...
	if dkimSignatureToValidate.QueryMethod != DEFAULT_QUERY_METHOD {
		fmt.Printf("currently only one query method is supported.%s", CRLF)
		fmt.Printf("unsupported query method encountered: got: %s - expected: %s%s%s", dkimSignatureToValidate.QueryMethod, DEFAULT_QUERY_METHOD, CRLF, CRLF)
		return TEMPFAIL, errors.New("query method for domain key not supported")
	}
	domainKeyLocation := fmt.Sprintf("%s._domainkey.%s", dkimSignatureToValidate.Selector, dkimSignatureToValidate.SigningDomainIdentifier)
	records, err := net.LookupTXT(domainKeyLocation)
	if err != nil {
		fmt.Printf("failed to retreive domain key from location %s: %s%s%s", domainKeyLocation, err.Error(), CRLF, CRLF)
		return TEMPFAIL, errors.New("error quering domain key")
	}
	numRecords := len(records)
	if numRecords == 0 {
		// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #3
		fmt.Printf("no txt record exists%s%s", CRLF, CRLF)
		return PERMFAIL, errors.New("query for domain key returned no results")
	}
	// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #4 we are opting to only try the first record.
	// the RFC leaves it to the implementers discression

	// parse domain key from record return from query method
	domainKey, err := ParseDomainKey([]byte(records[0]))
	if err != nil {
		// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item #5
		fmt.Printf("failed to parse domain key: %s%s%s", err.Error(), CRLF, CRLF)
		return PERMFAIL, err
	}
	// per https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2 item # 6
	// TODO: finish verifier steps...
	// check for y flag and return TEMPFAIL if it is present. Per https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1
	if domainKey.Flags.ContainsFlag(DomainKeyFlag_Y) {
		fmt.Printf("failing signature validation because y flag is present in domain key%s%s", CRLF, CRLF)
		return TEMPFAIL, errors.New("y flag present in dkim signature")
	}
	// https://datatracker.ietf.org/doc/html/rfc5451 looks like the value of i= for the DKIM-Signatures is stored over there...
	if domainKey.Flags.ContainsFlag(DomainKeyFlag_S) {
		// perform S flag validation.
		if len(dkimSignatureToValidate.AgentUserIdentifier) > 0 {
			domainPortionOfAUID := strings.Split(dkimSignatureToValidate.AgentUserIdentifier, "@")
			if len(domainPortionOfAUID) < 2 || domainPortionOfAUID[1] != dkimSignatureToValidate.SigningDomainIdentifier {
				fmt.Printf("AUID doamin %s does not match %s%s%s", domainPortionOfAUID[1], dkimSignatureToValidate.SigningDomainIdentifier, CRLF, CRLF)
				return PERMFAIL, errors.New("auid does not match sdid")
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
			fmt.Printf("skipping S flag AUID Signing Domain verification because i= flag is not populated on DKIM signature%s%s", CRLF, CRLF)
		}
	}
	canonicalizedDKIMSignature, err := canonicalizeHeader(dkimSignatureToValidate.Header, dkimSignatureToValidate.CanonicalizationAlgorithm)
	dkimSigForVerification := GetDKIMSignatureForVerificationOrSigningBytes(canonicalizedDKIMSignature)
	if err != nil {
		fmt.Printf("failed to canonicalize dkim signature for verification: %s%s%s", err.Error(), CRLF, CRLF)
		return PERMFAIL, errors.New("invalid dkim signature for canonicalization")
	}
	var computedSignatureHash []byte
	// var computedSignatureHashBase64 string
	var hashAlgo crypto.Hash
	hashBuffer := make([]byte, 0)
	hashBuffer = append(hashBuffer, canonicalizedHeaderData...)
	hashBuffer = append(hashBuffer, dkimSigForVerification...)
	// hashBuffer = append(hashBuffer, canonicalizedBodyHash...)
	switch dkimSignatureToValidate.Algorithm {
	case DKIM_ALGORITHM_RSA_SHA_1:
		hashAlgo = crypto.SHA1
		hash := sha1.Sum(hashBuffer)
		computedSignatureHash = hash[:]
		// computedSignatureHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	case DKIM_ALGORITHM_RSA_SHA_256:
		hashAlgo = crypto.SHA256
		hash := sha256.Sum256(hashBuffer)
		computedSignatureHash = hash[:]
		// computedSignatureHashBase64 = base64.StdEncoding.EncodeToString(canonicalizedBodyHash)
	}
	signatureToValidateBytes, err := base64.StdEncoding.DecodeString(dkimSignatureToValidate.Signature)
	if err != nil {
		fmt.Printf("failed to decode dkim signature from base 64%s%s", CRLF, CRLF)
		return TEMPFAIL, errors.New("failed to decode dkim signaure")
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(domainKey.PublicKey)
	if err != nil {
		fmt.Printf("failed to decode public key from base 64%s%s", CRLF, CRLF)
		return TEMPFAIL, errors.New("failed to base64 decode public key")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		log.Println("Could not parse DER encoded public key (encryption key)")
		return PERMFAIL, errors.New("invalid public key")
	}
	publicKey, isRSAPublicKey := publicKeyInterface.(*rsa.PublicKey)
	if !isRSAPublicKey {
		log.Println("Public key parsed is not an RSA public key")
		return PERMFAIL, errors.New("invalid public key")
	}
	err = rsa.VerifyPKCS1v15(publicKey, hashAlgo, computedSignatureHash, signatureToValidateBytes)
	if err != nil {
		fmt.Printf("Error from verification: %s%s", err, CRLF)
		return PERMFAIL, errors.New("verification failed")
	}
	return SUCCESS, nil
}
