package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

type inputArgs struct {
	inputEmailFile string
}

func main() {
	var inputArgs inputArgs
	flag.StringVar(&inputArgs.inputEmailFile, "inputFile", "", "The input email file for DKIM signature verification")
	flag.Parse()
	fmt.Printf("test call %v\n\n", inputArgs)
	fileData, err := ioutil.ReadFile(inputArgs.inputEmailFile)
	if err != nil {
		fmt.Printf("failed to open file %s: %s", inputArgs.inputEmailFile, err.Error())
		os.Exit(1)
		return
	}
	fileLength := len(fileData)
	if fileLength <= 0 {
		fmt.Printf("file contains no data!")
		os.Exit(2)
		return
	}
	fmt.Printf("file length: %d\n", fileLength)
}
