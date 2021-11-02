package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// TODO: make to string and from value method for each type aliased string

type DKIMVersion int

const (
	DKIM_VERSION_INVALID DKIMVersion = iota
	DKIM_VERSION_1
)

type DKIMAlgorithm int

const (
	DKIM_ALGORITHM_INVALID     DKIMAlgorithm = iota
	DKIM_ALGORITHM_RSA_SHA_1                 // "rsa-sha1"
	DKIM_ALGORITHM_RSA_SHA_256               //"rsa-sha256"
)

type DKIMCanonAlgorithm int

const (
	DKIM_CANON_ALGO_INVALID         DKIMCanonAlgorithm = iota
	DKIM_CANON_ALGO_SIMPLE                             //"simple"
	DKIM_CANON_ALGO_SIMPLE_SIMPLE                      // "simple/simple"
	DKIM_CANON_ALGO_RELAXED                            //"relaxed"
	DKIM_CANON_ALGO_RELAXED_RELAXED                    //"relaxed/relaxed"
	DKIM_CANON_ALGO_RELAXED_SIMPLE                     //"relaxed/simple"
	DKIM_CANON_ALGO_SIMPLE_RELAXED                     //"simple/relaxed"
)

const (
	DKIMSignatureHeaderName = "dkim-signature"

	// DEFAULT_BODY_LENGTH_LIMIT means there is no limit and the whole body should be use in signature validation
	DEFAULT_BODY_LENGTH_LIMIT = -1

	DEFAULT_QUERY_METHOD = "dns/txt"

	VersionKey                   = "v"
	AlgorithmKey                 = "a"
	SignatureKey                 = "b"
	BodySignatureKey             = "bh"
	CanonicalizationAlgorithmKey = "c"
	SigningDomainIdentifierKey   = "d"
	SignedHeadersKey             = "h"
	AgentUserIdentifierKey       = "i"
	BodyLengthLimitKey           = "l"
	QueryMethodKey               = "q"
	SelectorKey                  = "s"
	SignatureTimestampKey        = "t"
	SignatureExpirationKey       = "x"
	CopiedHeaderFieldsKey        = "z"
)

type DKIMSignature struct {
	Version                   int    `json:"v"`
	Algorithm                 string `json:"a"`
	Signature                 string `json:"b"`
	BodySignature             string `json:"bh"`
	CanonicalizationAlgorithm string `json:"c"`
	SigningDomainIdentifier   string `json:"d"`
	SignedHeaders             string `json:"h"`
	AgentUserIdentifier       string `json:"i"`
	BodyLengthLimit           int    `json:"l"`
	QueryMethod               string `json:"q"`
	Selector                  string `json:"s"`
	SignatureTimestamp        string `json:"t"`
	SignatureExpiration       string `json:"x"`
	CopiedHeaderFields        string `json:"z"`
}

// NewDKIMSignature is the proper way for creating a new DKIMSignature, and populates defaults.
func NewDKIMSignature() DKIMSignature {
	return DKIMSignature{
		BodyLengthLimit: DEFAULT_BODY_LENGTH_LIMIT,
		QueryMethod:     DEFAULT_QUERY_METHOD,
	}
}

func ParseDKIMSignature(header header) (DKIMSignature, error) {
	dkimSignature := NewDKIMSignature()
	headerName := header.getHeaderKey(true)
	if headerName != DKIMSignatureHeaderName {
		return dkimSignature, fmt.Errorf("header name is not what was expected:\ngot -\t%s\n expected -\t%s", headerName, DKIMSignatureHeaderName)
	}
	rawHeaderValue := header.getHeaderRawValueBytes()
	currentRuneIndex := 0
	lastSemicolonIndex := 0
	lastEqualsIndex := 0
	rawValueLength := len(rawHeaderValue)
	var key, value string
	for currentRuneIndex < rawValueLength {
		currentRune, width := utf8.DecodeRune(rawHeaderValue[currentRuneIndex:])
		currentRuneIndex += width
		if currentRune == '=' {
			rawKey := string(rawHeaderValue[lastSemicolonIndex : currentRuneIndex-width])
			key = strings.TrimSpace(rawKey)
			lastEqualsIndex = currentRuneIndex
		} else if currentRune == ';' {
			rawValue := string(rawHeaderValue[lastEqualsIndex : currentRuneIndex-width])
			value = strings.TrimSpace(rawValue)
			dkimSignature.AddValue(key, value)
			lastSemicolonIndex = currentRuneIndex
			key, value = "", ""
		}
	}
	return dkimSignature, nil
}

func (sig *DKIMSignature) AddValue(key, value string) error {
	switch key {
	case VersionKey:
		val, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return err
		}
		sig.Version = int(val)
		if sig.Version != 1 {
			return fmt.Errorf("the only permitted value of DKIM signature is 1: got - %d", sig.Version)
		}
	case AlgorithmKey:
		sig.Algorithm = value
	case SignatureKey:
		sig.Signature = value
	case BodySignatureKey:
		sig.BodySignature = value
	case CanonicalizationAlgorithmKey:
		sig.CanonicalizationAlgorithm = value
	case SigningDomainIdentifierKey:
		sig.SigningDomainIdentifier = value
	case SignedHeadersKey:
		sig.SignedHeaders = value
	case AgentUserIdentifierKey:
		sig.AgentUserIdentifier = value
	case BodyLengthLimitKey:
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return err
		}
		sig.BodyLengthLimit = int(val)
	case QueryMethodKey:
		sig.QueryMethod = value
	case SelectorKey:
		sig.Selector = value
	case SignatureTimestampKey:
		sig.SignatureTimestamp = value
	case SignatureExpirationKey:
		sig.SignatureExpiration = value
	case CopiedHeaderFieldsKey:
		sig.CopiedHeaderFields = value
	}
	return nil
}
