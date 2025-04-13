package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/picatz/taint/cmd/taint/example/features"
)

var ansiEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func removeANSICodes(input string) string {
	return ansiEscapeRegex.ReplaceAllString(input, "")
}

func main() {
	outputRoot := "output"
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the location of the subdirectory: ")
	location, _ := reader.ReadString('\n')
	location = strings.TrimSpace(location)

	err := filepath.Walk(location, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.Name() == "main.go" {
			dir := filepath.Dir(path)
			fmt.Printf("\nFound main.go in: %s\n", dir)

			ctx := context.Background()
			cg, loadErr := features.LoadCallGraph(ctx, dir, "./...")
			if loadErr != nil {
				fmt.Printf("Failed to load call graph for %s: %v\n", dir, loadErr)
				return nil
			}

			scanDirName := strings.ReplaceAll(filepath.Base(dir), string(os.PathSeparator), "_")
			outputDir := filepath.Join(outputRoot, scanDirName)
			os.MkdirAll(outputDir, os.ModePerm)

			// Write call graph
			func() {
				var buf bytes.Buffer
				writer := bufio.NewWriter(&buf)
				features.PrintCallGraph(ctx, writer, cg)
				writer.Flush()

				cleaned := removeANSICodes(buf.String())
				_ = os.WriteFile(filepath.Join(outputDir, "callgraph.txt"), []byte(cleaned), 0644)
			}()

			// Write root call graph
			func() {
				var buf bytes.Buffer
				writer := bufio.NewWriter(&buf)
				features.RootCallGraph(cg, ctx, writer)
				writer.Flush()

				cleaned := removeANSICodes(buf.String())
				_ = os.WriteFile(filepath.Join(outputDir, "rootgraph.txt"), []byte(cleaned), 0644)
			}()

			// Load sources and sinks
			sourceBytes, sourceErr := os.ReadFile("./sources.txt")
			sinkBytes, sinkErr := os.ReadFile("./sinks.txt")
			if sourceErr != nil || sinkErr != nil {
				fmt.Printf("Error reading source/sink files: %v, %v\n", sourceErr, sinkErr)
				return nil
			}

			sources := filterLines(string(sourceBytes))
			sinks := filterLines(string(sinkBytes))

			// Write Source and Sink checks
			sinkFilePath := filepath.Join(outputDir, "SourceAndSink.txt")
			sinkFile, err := os.Create(sinkFilePath)
			if err != nil {
				fmt.Printf("Failed to create SourceAndSink.txt: %v\n", err)
				return nil
			}
			defer sinkFile.Close()

			for _, src := range sources {
				for _, sink := range sinks {
					var buf bytes.Buffer
					writer := bufio.NewWriter(&buf)
					err := features.CheckSourceAndSink(src, sink, cg, ctx, writer)
					writer.Flush()

					cleaned := removeANSICodes(buf.String())
					sinkFile.WriteString(cleaned)

					if err != nil {
						fmt.Printf("Error checking %s → %s: %v\n", src, sink, err)
					}
				}
			}

			fmt.Printf("✔ Output written to: %s\n", outputDir)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the path: %v", err)
	}
}

func filterLines(input string) []string {
	lines := strings.Split(input, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
