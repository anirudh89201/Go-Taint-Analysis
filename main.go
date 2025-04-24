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

// xssMap defines common XSS sources and their corresponding sinks.
var xssMap = map[string][]string{
	"(*net/url.URL).Query": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*net/http.Request).FormValue": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"io.ReadAll": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"*http.Request": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"net/http.Request.Body": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.URL.Query()": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.URL.Query().Get(\"paramName\")": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.FormValue(\"paramName\")": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.Form.Get(\"paramName\")": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.Body": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"io.ReadAll(r.Body)": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.FormValue": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.URL": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.URL.Query().Get(\"input\")": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"r.FormValue(\"formField\")": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*net/url.URL).Query().Get": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*net/http.Request).Form.Get": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*http.Request).Body": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*net/http.Request).Header.Get": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(*net/http.Request).Cookie": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"io.ReadAll.(*http.Request).Body": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
	"(net/url.Values).Get": {
		"w.Write",
		"w.Write([]byte)",
		"w.Write(b)",
		"(io.Writer).Write",
		"io.Copy(w, buffer(r.Body))",
		"io.WriteString(w, r.URL.Query().Get(\"q\"))",
	},
}

// logInjectionMap defines sources and their corresponding logging sinks for log injection detection.
var logInjectionMap = map[string][]string{
	"(*net/url.URL).Query": {
		"(*log.Logger).Println",
		"log.Println",
		"(*log/slog.Logger).InfoContext",
		"(*slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/http.Request).FormValue": {
		"(*log.Logger).Println",
		"log.Println",
		"(*log/slog.Logger).InfoContext",
		"(*slog.Logger).InfoContext",
		"slog.Info",
	},
	"io.ReadAll": {
		"(*log.Logger).Println",
		"log.Println",
		"(*log/slog.Logger).InfoContext",
		"(*slog.Logger).InfoContext",
		"slog.Info",
	},
	"*http.Request": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"net/http.Request.Body": {
		"(*log.Logger).Println",
		"log.Println",
		"(*log/slog.Logger).InfoContext",
		"(*slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.URL.Query()": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"slog.Info",
		"(*log/slog.Logger).InfoContext",
	},
	"r.URL.Query().Get(\"input\")": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"slog.Info",
		"(*log/slog.Logger).InfoContext",
	},
	"r.URL.Query().Get(\"paramName\")": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"slog.Info",
		"(*log/slog.Logger).InfoContext",
	},
	"r.URL.User.Password()": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.FormValue(\"paramName\")": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.Form.Get(\"paramName\")": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"os.Args": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"os.Args[1]": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.Body": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"io.ReadAll(r.Body)": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.FormValue": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.URL": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/url.Userinfo).Password": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"r.FormValue(\"formField\")": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/url.URL).Query().Get": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/http.Request).Form.Get": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*http.Request).Body": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/http.Request).Header.Get": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(*net/http.Request).Cookie": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"io.ReadAll.(*http.Request).Body": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
	"(net/url.Values).Get": {
		"(*log.Logger).Println",
		"log.Println",
		"(*slog.Logger).InfoContext",
		"(*log/slog.Logger).InfoContext",
		"slog.Info",
	},
}

// sqlInjectionMap defines sources and their corresponding SQL sinks for SQL injection detection.
var sqlInjectionMap = map[string][]string{
	"(*net/http.Request).FormValue": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL.User.Password()": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.FormValue(\"paramName\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.Form.Get(\"paramName\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.FormValue": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
	},
	"r.FormValue(\"formField\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL.Query()": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL.Query().Get(\"paramName\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL.Query().Get(\"q\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL.Query().Get(\"input\")": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"(*net/url.URL).Query().Get": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"(net/url.Values).Get": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.Body": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"net/http.Request.Body": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"(*http.Request).Body": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"io.ReadAll(r.Body)": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"io.ReadAll.(*http.Request).Body": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"*http.Request": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"r.URL": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"(*net/http.Request).Header.Get": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"(*net/http.Request).Cookie": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"os.Args": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"os.Args[1]": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},

	"(*net/url.Userinfo).Password": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"echo(w, r)": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"echo(w, r.Body)": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"github.com/picatz/taint/sql/injection/testdata/src/h.realMain$1$1": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
	"github.com/picatz/taint/sql/injection/testdata/src/h.realMain$1": {
		"(*database/sql.DB).Query",
		"(*sql.DB).Query",
		"(*database/sql.DB).Exec",
		"(*github.com/jinzhu/gorm.DB).Where",
		"db.Query",
		"db.Query(q)",
	},
}

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

			// Create results.txt file
			resultsFilePath := filepath.Join(outputDir, "results.txt")
			resultsFile, err := os.Create(resultsFilePath)
			if err != nil {
				fmt.Printf("Failed to create results.txt: %v\n", err)
				return nil
			}
			defer resultsFile.Close()

			resultsWriter := bufio.NewWriter(resultsFile)

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

					// For each source-sink pair logged, find their line numbers in .go files
					sourceLineNumbers := findLineNumbers(dir, src)
					sinkLineNumbers := findLineNumbers(dir, sink)

					// Log the results with line numbers to results.txt
					for _, sourceLine := range sourceLineNumbers {
						for _, sinkLine := range sinkLineNumbers {
							resultLine := fmt.Sprintf("Tainted flow detected! Source: %s at line %d, Sink: %s at line %d", src, sourceLine, sink, sinkLine)
							// Check if the source-sink pair is in xssMap
							for _, xssSink := range xssMap[src] {
								if sink == xssSink {
									resultLine += " Potential XSS vulnerability"
									break
								}
							}
							// Check if the source-sink pair is in logInjectionMap
							for _, logSink := range logInjectionMap[src] {
								if sink == logSink {
									resultLine += " Potential log injection vulnerability"
									break
								}
							}
							// Check if the source-sink pair is in sqlInjectionMap
							for _, sqlSink := range sqlInjectionMap[src] {
								if sink == sqlSink {
									resultLine += " Potential SQL injection vulnerability"
									break
								}
							}
							resultsWriter.WriteString(resultLine + "\n")
						}
					}
				}
			}

			// Ensure all content is written to the file
			resultsWriter.Flush()

			fmt.Printf("✔ Output written to: %s\n", outputDir)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the path: %v", err)
	}
}

func findLineNumbers(dirPath, searchStr string) []int {
	var lineNumbers []int
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") {
			file, err := os.Open(path)
			if err != nil {
				fmt.Printf("Error opening file %s: %v\n", path, err)
				return nil
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			lineNumber := 0
			for scanner.Scan() {
				lineNumber++
				line := scanner.Text()
				if strings.Contains(line, searchStr) {
					lineNumbers = append(lineNumbers, lineNumber)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading file %s: %v\n", path, err)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error walking directory %s: %v\n", dirPath, err)
	}
	return lineNumbers
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
