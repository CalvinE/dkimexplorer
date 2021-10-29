package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"unicode/utf8"
)

type inputArgs struct {
	inputEmailFile string
}

type ParserState uint8

const (
	Unset ParserState = iota
	AlphaNumeric
	WhiteSpace
	CarrageReturn
	LineFeed
)

const (
	cr  = '\r'
	lf  = '\n'
	sp  = ' '
	tab = '\t'

	colon = ':'
)

var (
	parserState = Unset
)

func main() {
	var inputArgs inputArgs
	flag.StringVar(&inputArgs.inputEmailFile, "inputFile", "", "The input email file for DKIM signature verification")
	flag.Parse()
	fmt.Printf("test call %v\n", inputArgs)
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
	for i := 0; i < 150; {
		// decode text as UTF-8 to handle a wide variety of characters in text?
		r, width := utf8.DecodeRune(fileData[i : i+1])
		fmt.Println(i, "\t", r, "\t", string(r))
		i += width
	}
}

// func ByteIsNonCRLFWhitespace(b byte) bool {
// 	switch b {
// 	case '\t':

// 	}
// }
