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

type header struct {
	AbsoluteStartIndex, AbsoluteEndIndex, HeaderLength uint

	FoldingWhiteSpaceRelativeStartIndexes []uint
	HeaderBytes                           []byte
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

	nonCRLFWhitespace = map[rune]struct{}{
		sp:  {},
		tab: {},
	}
)

func main() {
	var inputArgs inputArgs
	flag.StringVar(&inputArgs.inputEmailFile, "inputFile", "sample_email.txt", "The input email file for DKIM signature verification")
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
	var i int
	// parse headers

	// currentLineIndex helps us keep track of how many characters in a header we are
	var currentHeaderIndex uint = 0
	var headers []header
	currentHeader := &header{}
	var previousRune rune
	for i < fileLength {
		// decode text as UTF-8 to handle a wide variety of characters in text?
		currentRune, width := utf8.DecodeRune(fileData[i:])
		// fmt.Println(i, "\t", currentRune, "\t", string(currentRune), "\t", width)
		i += width
		currentHeaderIndex += uint(width)
		if currentRune == lf {
			// we hit a line feed.
			if previousRune == cr && i < fileLength {
				// we are not at the end of the file and the previous rune was a CR.
				if currentHeaderIndex == 2 {
					// end of headers... Designated by an empty line
					break
				}
				// the preivous character was a carrage return!
				nextRune, width2 := utf8.DecodeRune(fileData[i:])
				// fmt.Println(i, "\t", nextRune, "\t", string(nextRune), "\t", width2)
				_, ok := nonCRLFWhitespace[nextRune]
				if ok {
					// current index is part of folding white space
					// because the first character on the next line is white space.
					// we want to capture the index of the folding whitespace CR
					// so we can quickly get to it later.
					currentHeader.FoldingWhiteSpaceRelativeStartIndexes = append(currentHeader.FoldingWhiteSpaceRelativeStartIndexes, currentHeaderIndex)
					currentHeaderIndex += uint(width2)
				} else {
					// This is not folding white space, so it must be a new header!
					// current index is end of header
					currentHeader.AbsoluteEndIndex = uint(i)
					currentHeader.HeaderBytes = make([]byte, currentHeaderIndex)
					currentHeader.HeaderLength = currentHeaderIndex
					// copying all header bytes into byte slice in the header struct
					// so we can play with it later.
					// I made a symantic choice here. the way slicing works here is the number
					// after the : is like saying up to but not including that item
					// I may come back and change this so that the end index in the slicing below
					// adds one to the end index and makes this value the actual end of the header,
					// but I think I am over thinking it so I will leave it be for now. for our
					// purposes it works fine...
					_ = copy(currentHeader.HeaderBytes, fileData[currentHeader.AbsoluteStartIndex:currentHeader.AbsoluteEndIndex])
					// fmt.Printf("%d copied \n", copied)
					headers = append(headers, *currentHeader)
					currentHeader = &header{
						AbsoluteStartIndex: uint(i),
					}
					currentHeaderIndex = uint(1)
				}
				// increment out file position index and our previous run since we skipped one ahead
				i += width2
				previousRune = nextRune
				continue
			} else {
				// end of file?
				fmt.Println("Encountered end of file while parsing headers???")
				os.Exit(3)
				break
			}
		}
		previousRune = currentRune
	}

	for i, header := range headers {
		// fmt.Printf("%d - header:\t %v\n", i, header)
		fmt.Printf("%d:\t %s", i+1, header.HeaderBytes)
	}

	// read body
}

// func ByteIsNonCRLFWhitespace(b byte) bool {
// 	switch b {
// 	case '\t':

// 	}
// }
