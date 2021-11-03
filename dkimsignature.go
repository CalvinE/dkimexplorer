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
		return "relaed/relaxed"
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
	Version                   DKIMVersion        `json:"v"`
	Algorithm                 DKIMAlgorithm      `json:"a"`
	Signature                 string             `json:"b"`
	BodySignature             string             `json:"bh"`
	CanonicalizationAlgorithm DKIMCanonAlgorithm `json:"c"`
	SigningDomainIdentifier   string             `json:"d"`
	SignedHeaders             string             `json:"h"`
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
		BodyLengthLimit: DEFAULT_BODY_LENGTH_LIMIT,
		QueryMethod:     DEFAULT_QUERY_METHOD,
	}
}

// TODO: refactor to pull out this parsing logic as it is shared with the domain key parser.
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
		if currentRune == '=' && lastEqualsIndex == 0 {
			rawKey := string(rawHeaderValue[lastSemicolonIndex : currentRuneIndex-width])
			key = strings.TrimSpace(rawKey)
			lastEqualsIndex = currentRuneIndex
		} else if currentRune == ';' {
			rawValue := string(rawHeaderValue[lastEqualsIndex : currentRuneIndex-width])
			value = strings.TrimSpace(rawValue)
			dkimSignature.AddValue(key, value)
			lastSemicolonIndex = currentRuneIndex
			lastEqualsIndex = 0
			key, value = "", ""
		}
	}
	return dkimSignature, nil
}

func (sig *DKIMSignature) AddValue(key, value string) error {
	switch key {
	case DKIMSignature_VersionKey:
		val := value
		sig.Version = DKIMVersionValue(val)
		if sig.Version != DKIM_VERSION_1 {
			return fmt.Errorf("the only permitted value of DKIM signature is 1: got - %d", sig.Version)
		}
	case DKIMSignature_AlgorithmKey:
		sig.Algorithm = DKIMAlgorithmValue(value)
		if sig.Algorithm == DKIM_ALGORITHM_INVALID {
			return fmt.Errorf("invalid DKIM signing algorithm specified: %s", value)
		}
	case DKIMSignature_SignatureKey:
		sig.Signature = value
	case DKIMSignature_BodySignatureKey:
		sig.BodySignature = value
	case DKIMSignature_CanonicalizationAlgorithmKey:
		sig.CanonicalizationAlgorithm = DKIMCanonAlgoValue(value)
		if sig.CanonicalizationAlgorithm == DKIM_CANON_ALGO_INVALID {
			return fmt.Errorf("invalid canonicalization algorithm specified: %s", value)
		}
	case DKIMSignature_SigningDomainIdentifierKey:
		sig.SigningDomainIdentifier = value
	case DKIMSignature_SignedHeadersKey:
		sig.SignedHeaders = value
	case DKIMSignature_AgentUserIdentifierKey:
		sig.AgentUserIdentifier = value
	case DKIMSignature_BodyLengthLimitKey:
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return err
		}
		sig.BodyLengthLimit = int(val)
	case DKIMSignature_QueryMethodKey:
		sig.QueryMethod = value
	case DKIMSignature_SelectorKey:
		sig.Selector = value
	case DKIMSignature_SignatureTimestampKey:
		sig.SignatureTimestamp = value
	case DKIMSignature_SignatureExpirationKey:
		sig.SignatureExpiration = value
	case DKIMSignature_CopiedHeaderFieldsKey:
		sig.CopiedHeaderFields = value
	}
	return nil
}