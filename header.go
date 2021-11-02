package main

import (
	"strings"
	"unicode/utf8"
)

type header struct {
	AbsoluteStartIndex                    uint
	AbsoluteEndIndex                      uint
	HeaderLength                          uint
	RelativeSeperatorIndex                uint
	FoldingWhiteSpaceRelativeStartIndexes []uint
	RawHeaderBytes                        []byte
}

func (header *header) getHeaderKey(normalize bool) string {
	key := string(header.RawHeaderBytes[:header.RelativeSeperatorIndex])
	if normalize {
		return strings.TrimSpace(strings.ToLower(key))
	}
	return strings.TrimSpace(key)
}

func (header *header) getHeaderRawValueBytes() []byte {
	colonLength := utf8.RuneLen(colon)
	rawValue := header.RawHeaderBytes[header.RelativeSeperatorIndex+uint(colonLength):]
	return rawValue
}

func (header *header) getHeaderRawValueString() string {
	value := header.getHeaderRawValueBytes()
	return string(value)
}

func (header *header) getHeaderTrimmedValue() string {
	value := header.getHeaderRawValueString()
	return strings.TrimSpace(value)
}
