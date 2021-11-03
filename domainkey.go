package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

type DomainKeyVersion int

const (
	DomainKeyVersion_INVALID DomainKeyVersion = iota
	DomainKeyVersion_DKIM1
)

func (v DomainKeyVersion) String() string {
	switch v {
	case DomainKeyVersion_DKIM1:
		return "DKIM1"
	default:
		return "INVALID"
	}
}

func DomainKeyVersionValue(s string) DomainKeyVersion {
	versionString := strings.ToUpper(strings.TrimSpace(s))
	switch versionString {
	case "DKIM1":
		return DomainKeyVersion_DKIM1
	default:
		return DomainKeyVersion_INVALID
	}
}

type DomainKeyKeyType int

const (
	DomainKeyKeyType_INVALID DomainKeyKeyType = iota
	DomainKeyKeyType_RSA
)

func (v DomainKeyKeyType) String() string {
	switch v {
	case DomainKeyKeyType_RSA:
		return "rsa"
	default:
		return "INVALID"
	}
}

func DomainKeyKeyTypeValue(s string) DomainKeyKeyType {
	versionString := strings.ToLower(strings.TrimSpace(s))
	switch versionString {
	case "rsa":
		return DomainKeyKeyType_RSA
	default:
		return DomainKeyKeyType_INVALID
	}
}

type DomainKeyFlag int

const (
	DomainKeyFlag_INVALID DomainKeyFlag = 1
	DomainKeyFlag_Y       DomainKeyFlag = 2
	DomainKeyFlag_S       DomainKeyFlag = 4
)

func (v DomainKeyFlag) String() string {
	switch v {
	case DomainKeyFlag_Y:
		return "y"
	case DomainKeyFlag_S:
		return "s"
	default:
		return "INVALID"
	}
}

func (v DomainKeyFlag) ContainsFlag(f DomainKeyFlag) bool {
	return v&f != 0
}

func DomainKeyFlagValue(s string) DomainKeyFlag {
	versionString := strings.ToLower(strings.TrimSpace(s))
	switch versionString {
	case "y":
		return DomainKeyFlag_Y
	case "s":
		return DomainKeyFlag_S
	default:
		return DomainKeyFlag_INVALID
	}
}

type DomainKey struct {
	Version DomainKeyVersion `json:"v"`
	// AcceptableHashAlgorithms colon seperated list of algorithms. defaults to allow all algorithms
	AcceptableHashAlgorithms []string         `json:"h"`
	KeyType                  DomainKeyKeyType `json:"k"`
	Notes                    string           `json:"n"`
	PublicKey                string           `json:"p"`
	ServiceType              string           `json:"s"`
	// Flags defaults to no flags set.
	Flags DomainKeyFlag `json:"t"`
}

const (
	DomainKey_VersionKey                  = "v"
	DomainKey_AcceptableHashAlgorithmsKey = "h"
	DomainKey_KeyTypeKey                  = "k"
	DomainKey_NotesKey                    = "n"
	DomainKey_PublicKeyKey                = "p"
	DomainKey_ServiceTypeKey              = "s"
	DomainKey_FlagsKey                    = "t"
)

func NewDomainKey() DomainKey {
	return DomainKey{
		Version:                  DomainKeyVersion_DKIM1,
		AcceptableHashAlgorithms: []string{"*"},
		KeyType:                  DomainKeyKeyType_RSA,
		ServiceType:              "*",
	}
}

func ParseDomainKey(domainKeyBytes []byte) (DomainKey, error) {
	domainKey := NewDomainKey()
	currentRuneIndex := 0
	lastSemicolonIndex := 0
	lastEqualsIndex := 0
	rawValueLength := len(domainKeyBytes)
	var key, value string
	for currentRuneIndex < rawValueLength {
		currentRune, width := utf8.DecodeRune(domainKeyBytes[currentRuneIndex:])
		currentRuneIndex += width
		if currentRune == '=' && lastEqualsIndex == 0 {
			rawKey := string(domainKeyBytes[lastSemicolonIndex : currentRuneIndex-width])
			key = strings.TrimSpace(rawKey)
			lastEqualsIndex = currentRuneIndex
		} else if currentRune == ';' {
			rawValue := string(domainKeyBytes[lastEqualsIndex : currentRuneIndex-width])
			value = strings.TrimSpace(rawValue)
			domainKey.AddValue(key, value)
			lastSemicolonIndex = currentRuneIndex
			lastEqualsIndex = 0
			key, value = "", ""
		}
	}
	if lastEqualsIndex != 0 {
		// unterminated field in domain key data.
		rawValue := string(domainKeyBytes[lastEqualsIndex:])
		value = strings.TrimSpace(rawValue)
		domainKey.AddValue(key, value)
	}
	return domainKey, nil
}

func (dkey *DomainKey) AddValue(key, value string) error {
	switch key {
	case DomainKey_VersionKey:
		dkey.Version = DomainKeyVersionValue(value)
		if dkey.Version == DomainKeyVersion_INVALID {
			return fmt.Errorf("invalid version in domain key: %s", value)
		}
	case DomainKey_AcceptableHashAlgorithmsKey:
		values := strings.Split(value, ":")
		dkey.AcceptableHashAlgorithms = values
	case DomainKey_KeyTypeKey:
		dkey.KeyType = DomainKeyKeyTypeValue(value)
		if dkey.KeyType == DomainKeyKeyType_INVALID {
			return fmt.Errorf("invalid key type in domain key: %s", value)
		}
	case DomainKey_NotesKey:
		dkey.Notes = value
	case DomainKey_PublicKeyKey:
		dkey.PublicKey = value
		if len(dkey.PublicKey) == 0 {
			return errors.New("public key provided has no data")
		}
	case DomainKey_ServiceTypeKey:
		dkey.ServiceType = value
	case DomainKey_FlagsKey:
		flags := strings.Split(value, ":")
		for _, f := range flags {
			val := DomainKeyFlagValue(f)
			dkey.Flags |= val
		}
		if dkey.Flags.ContainsFlag(DomainKeyFlag_INVALID) {
			return fmt.Errorf("invalid flag in domain key: %s", value)
		}
	}
	return nil
}
