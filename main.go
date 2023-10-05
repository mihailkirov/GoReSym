/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	// we copy the go src directly, then change every include to github.com/mihailkirov/GoReSym/<whatever>
	// this is required since we're using internal files. Our modifications are directly inside the copied source
	"github.com/mihailkirov/GoReSym/extractor"
)

func printForHuman(metadata extractor.ExtractMetadata) {
	fmt.Println("----GoReSym----")
	fmt.Println("Some information is omitted, for a full listing do not use human view")
	fmt.Printf("%-20s %s\n", "Version:", metadata.Version)
	fmt.Printf("%-20s %s\n", "Arch:", metadata.Arch)
	fmt.Printf("%-20s %s\n", "OS:", metadata.OS)
	fmt.Println("\n-BUILD INFO-")
	fmt.Printf("%-20s %s\n", "GoVersion", metadata.BuildInfo.GoVersion)
	fmt.Printf("%-20s %s\n", "Path", metadata.BuildInfo.Path)
	fmt.Printf("%-20s %s\n", "Main.Path", metadata.BuildInfo.Main.Path)
	fmt.Printf("%-20s %s\n", "Main.Version", metadata.BuildInfo.Main.Version)
	fmt.Printf("%-20s %s\n", "Main.Sum", metadata.BuildInfo.Main.Sum)
	fmt.Printf("%-20s %s\n", "Main.Path", metadata.BuildInfo.Main.Path)
	for i, dep := range metadata.BuildInfo.Deps {
		depPrefix := fmt.Sprintf("Dep%d.", i)
		fmt.Printf("%-20s %s\n", depPrefix+"Path", dep.Path)
		fmt.Printf("%-20s %s\n", depPrefix+"Version", dep.Version)
		fmt.Printf("%-20s %s\n", depPrefix+"Sum", dep.Sum)
	}

	fmt.Println("\n  -BUILD SETTINGS-")
	if len(metadata.BuildInfo.Settings) > 0 {
		for _, setting := range metadata.BuildInfo.Settings {
			fmt.Printf("  %-20s %s\n", "Setting."+setting.Key, setting.Value)
		}
	} else {
		fmt.Println("  <NO SETTINGS PRESENT>")
	}

	fmt.Println("\n-TYPE STRUCTURES-")
	printedStruct := false
	for _, typ := range metadata.Types {
		if len(typ.Reconstructed) > 0 {
			fmt.Printf("VA: 0x%x\n", typ.VA)
			fmt.Printf("%s\n\n", typ.Reconstructed)
			printedStruct = true
		}
	}
	if !printedStruct {
		fmt.Println("<NO TYPE STRUCTURES EXTRACTED>")
	}

	fmt.Println("\n-INTERFACES-")
	printedInterface := false
	for _, typ := range metadata.Interfaces {
		if len(typ.Reconstructed) > 0 {
			fmt.Printf("%-20s 0x%x\n", "VA:", typ.VA)
			fmt.Printf("%s\n\n", typ.Reconstructed)
			printedInterface = true
		}
	}
	if !printedInterface {
		fmt.Println("<NO INTERFACES EXTRACTED>")
	}

	fmt.Println("\n-Files-")
	if len(metadata.Files) > 0 {
		for _, file := range metadata.Files {
			fmt.Println(file)
		}
	} else {
		fmt.Println("<NO FILES EXTRACTED>")
	}

	fmt.Println("\n-User Functions-")
	if len(metadata.UserFunctions) > 0 {
		for i, fn := range metadata.UserFunctions {
			fnPrefix := fmt.Sprintf("UserFunc%d.", i)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"StartVA:", fn.Start)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"EndVA:", fn.End)
			fmt.Printf("%-20s %s\n", fnPrefix+"Package:", fn.PackageName)
			fmt.Printf("%-20s %s\n", fnPrefix+"Name:", strings.TrimLeft(strings.TrimLeft(fn.FullName, fn.PackageName), "."))
		}
	} else {
		fmt.Println("<NO USER FUNCTIONS EXTRACTED>")
	}

	fmt.Println("\n-Standard Functions-")
	if len(metadata.StdFunctions) > 0 {
		for i, fn := range metadata.StdFunctions {
			fnPrefix := fmt.Sprintf("StdFunc%d.", i)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"StartVA:", fn.Start)
			fmt.Printf("%-20s 0x%x\n", fnPrefix+"EndVA:", fn.End)
			fmt.Printf("%-20s %s\n", fnPrefix+"Name:", fn.FullName)
		}
	} else {
		fmt.Println("<NO STANDARD FUNCTIONS EXTRACTED>")
	}
}

func DataToJson(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "{\"error\": \"failed to format output\"}"
	}
	return string(jsonBytes)
}

func TextToJson(key string, text string) string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", key, text)
}

func main() {
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()

	log.SetFlags(0)
	log.SetPrefix("GoReSym: ")

	printStdPkgs := flag.Bool("d", false, "Print Default Packages")
	printFilePaths := flag.Bool("p", false, "Print File Paths")
	printTypes := flag.Bool("t", false, "Print types automatically, enumerate typelinks and itablinks")
	typeAddress := flag.Int("m", 0, "Manually parse the RTYPE at the provided virtual address, disables automated enumeration of moduledata typelinks itablinks")
	versionOverride := flag.String("v", "", "Override the automated version detection, ex: 1.17. If this is wrong, parsing may fail or produce nonsense")
	humanView := flag.Bool("human", false, "Human view, print information flat rather than json, some information is omitted for clarity")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println(TextToJson("error", "filepath must be provided as first argument"))
		os.Exit(1)
	}

	metadata, err := extractor.ExtractSymbols(flag.Arg(0), *printStdPkgs, *printFilePaths, *printTypes, *typeAddress, *versionOverride)
	if err != nil {
		fmt.Println(TextToJson("error", fmt.Sprintf("Failed to parse file: %s", err)))
		os.Exit(1)
	} else {
		if *humanView {
			printForHuman(*metadata)
		} else {
			fmt.Println(DataToJson((*metadata)))
		}
	}
}
