package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/cmd/taint/example/features"
	"golang.org/x/tools/go/callgraph"
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

			// Create results.txt file
			resultsFilePath := filepath.Join(outputDir, "results.txt")
			resultsFile, err := os.Create(resultsFilePath)
			if err != nil {
				fmt.Printf("Failed to create results.txt: %v\n", err)
				return nil
			}
			defer resultsFile.Close()

			resultsWriter := bufio.NewWriter(resultsFile)

			// Run log injection detection logic from logi.go
			logInjectionResults, logErr := RunLogInjectionCheck(cg)
			if logErr != nil {
				fmt.Printf("Error running log injection check: %v\n", logErr)
				return nil
			}

			for _, result := range logInjectionResults {
				resultsWriter.WriteString(string(result.SinkValue.Pos()) + "potential log injection")
			}
			XSSResults, XSSError := RunXSSCheck(cg)
			if XSSError != nil {
				fmt.Printf("Error running log injection check: %v\n", logErr)
				return nil
			}
			fset := token.NewFileSet() // WARNING: won't work properly without adding files

			for _, result := range XSSResults {
				pos := fset.Position(result.SinkValue.Pos())
				srcPos := fset.Position(result.SourceValue.Pos())
				line := fmt.Sprintf("XSS Injection Path:\n  Source at %s:%d\n  Sink at %s:%d\n\n",
					srcPos.Filename, srcPos.Line, pos.Filename, pos.Line)
				resultsWriter.WriteString(line)
			}

			SqlResults, SqlError := RunSqlCheck(cg)
			if SqlError != nil {
				fmt.Printf("Error running log injection check: %v\n", logErr)
				return nil
			}

			for _, result := range SqlResults {
				resultsWriter.WriteString(string(result.SinkValue.Pos()) + "potential Sql injection")
			}
			// Write Source and Sink checks
			sinkFilePath := filepath.Join(outputDir, "DataRoute.txt")
			sinkFile, err := os.Create(sinkFilePath)
			if err != nil {
				fmt.Printf("Failed to create SourceAndSink.txt: %v\n", err)
				return nil
			}
			defer sinkFile.Close()

			// Process sources and sinks for SourceSink check
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

					// For each source-sink pair, find their line numbers
					sourceLineNumbers := findLineNumbers(dir, src)
					sinkLineNumbers := findLineNumbers(dir, sink)

					// Log results in SourceAndSink
					for _, sourceLine := range sourceLineNumbers {
						for _, sinkLine := range sinkLineNumbers {
							resultLine := fmt.Sprintf("Tainted flow detected! Source: %s at line %d, Sink: %s at line %d", src, sourceLine, sink, sinkLine)
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
func RunLogInjectionCheck(cg *callgraph.Graph) ([]taint.Result, error) {
	var userControlledValues = taint.NewSources(
		"*net/http.Request",
	)

	var injectableLogFunctions = taint.NewSinks(
		// Note: at this time, they *must* be a function or method.
		"log.Fatal",
		"log.Fatalf",
		"log.Fatalln",
		"log.Panic",
		"log.Panicf",
		"log.Panicln",
		"log.Print",
		"log.Printf",
		"log.Println",
		"log.Output",
		"log.SetOutput",
		"log.SetPrefix",
		"log.Writer",
		"(*log.Logger).Fatal",
		"(*log.Logger).Fatalf",
		"(*log.Logger).Fatalln",
		"(*log.Logger).Panic",
		"(*log.Logger).Panicf",
		"(*log.Logger).Panicln",
		"(*log.Logger).Print",
		"(*log.Logger).Printf",
		"(*log.Logger).Println",
		"(*log.Logger).Output",
		"(*log.Logger).SetOutput",
		"(*log.Logger).SetPrefix",
		"(*log.Logger).Writer",

		// log/slog (structured logging)
		// https://pkg.go.dev/log/slog
		"log/slog.Debug",
		"log/slog.DebugContext",
		"log/slog.Error",
		"log/slog.ErrorContext",
		"log/slog.Info",
		"log/slog.InfoContext",
		"log/slog.Warn",
		"log/slog.WarnContext",
		"log/slog.Log",
		"log/slog.LogAttrs",
		"(*log/slog.Logger).With",
		"(*log/slog.Logger).Debug",
		"(*log/slog.Logger).DebugContext",
		"(*log/slog.Logger).Error",
		"(*log/slog.Logger).ErrorContext",
		"(*log/slog.Logger).Info",
		"(*log/slog.Logger).InfoContext",
		"(*log/slog.Logger).Warn",
		"(*log/slog.Logger).WarnContext",
		"(*log/slog.Logger).Log",
		"(*log/slog.Logger).LogAttrs",
		"log/slog.NewRecord",
		"(*log/slog.Record).Add",
		"(*log/slog.Record).AddAttrs",

		// TODO: consider adding the following logger packages,
		//       and the ability to configure this list generically.
		//
		// https://pkg.go.dev/golang.org/x/exp/slog
		// https://pkg.go.dev/github.com/golang/glog
		// https://pkg.go.dev/github.com/hashicorp/go-hclog
		// https://pkg.go.dev/github.com/sirupsen/logrus
		// https://pkg.go.dev/go.uber.org/zap
		// ...
	)

	// Run taint analysis using provided sources and sinks
	results := taint.Check(cg, userControlledValues, injectableLogFunctions)
	return results, nil
}
func RunXSSCheck(cg *callgraph.Graph) ([]taint.Result, error) {
	var userControlledValues = taint.NewSources(
		// User input in HTTP requests
		"(*net/http.Request).FormValue",       // Form values from HTTP requests
		"(*net/http.Request).URL.Query()",     // URL query parameters (e.g., r.URL.Query().Get("param"))
		"(*net/http.Request).URL.Query().Get", // Specific query parameter (e.g., r.URL.Query().Get("id"))
		"(*net/http.Request).Form",            // All form fields from the request
		"(*net/http.Request).PostForm",        // All POST form fields
		"(*net/http.Request).Header.Get",      // HTTP headers (could contain user-controlled input like User-Agent)
		"(*net/http.Request).Cookie",          // Cookies that may include user-controlled data
		"r.FormValue",                         // Form values (POST request)
		"r.URL.Query().Get('paramName')",      // Query parameter from URL (e.g., GET request)
		"os.Args",                             // Command-line arguments
		"os.Args[1]",                          // Specific command-line argument
		"r.Form.Get('paramName')",             // Specific form parameter
		"r.URL.User.Password()",               // Password from URL userinfo (if any)
		"r.FormValue('paramName')",            // Specific form field value
		"r.URL.Query().Get('input')",          // Query parameter with user input
		"r.Body",                              // Raw request body (could contain user-controlled data)
		"r.FormValue('formField')",            // A specific form field's value
		"(*net/url.URL).Query",                // Entire query of the URL
		"(*net/http.Request).Body",            // HTTP request body
	)

	var xssSinks = taint.NewSinks(
		// Direct insertion into HTML/DOM (could lead to XSS)
		"html/template.Execute",                                           // HTML template rendering
		"html/template.ExecuteTemplate",                                   // HTML template rendering
		"template.Execute",                                                // Go's text/template or html/template rendering
		"template.ExecuteTemplate",                                        // Go's text/template or html/template rendering
		"(*http.ResponseWriter).Write",                                    // Writing directly to HTTP response
		"(*http.ResponseWriter).WriteHeader",                              // Writing HTTP response headers
		"(*http.ResponseWriter).Write([]byte(...))",                       // Writing user input as a byte slice to response body
		"(*http.ResponseWriter).Write([]byte(str))",                       // Writing potentially tainted data to response body
		"(*http.ResponseWriter).Write([]byte(r.URL.Query().Get('q')))",    // Writing tainted query parameter
		"(*http.ResponseWriter).Write([]byte(r.FormValue('formField'))) ", // Writing tainted form field value
		"(*http.ResponseWriter).Write([]byte(formInput))",                 // Writing tainted form input
		"(*http.ResponseWriter).Write([]byte(queryInput))",                // Writing tainted query input
		"(*http.ResponseWriter).Write([]byte(str))",                       // Writing tainted string
		"html/template.HTML",                                              // HTML-escaping helper (if used improperly, can lead to XSS)
		"html/template.HTMLAttr",                                          // For inserting values into HTML attributes
		"javascript:",                                                     // If inserting user input into JavaScript
		"window.location.href",                                            // If setting window.location with user-controlled data
		"document.write",                                                  // Using document.write with user-controlled input
		"eval",                                                            // Using eval with user-controlled input
		"setTimeout",                                                      // Using setTimeout with user-controlled input
		"setInterval",                                                     // Using setInterval with user-controlled input
		"document.createElement",                                          // Dynamic DOM creation with user-controlled input
		"document.body.innerHTML",                                         // Writing directly to the inner HTML of the body (XSS risk)
		"document.getElementById().innerHTML",                             // Writing to innerHTML (XSS vulnerability)
		"document.getElementById().innerText",                             // Writing to innerText (XSS vulnerability)
		"document.getElementById().textContent",                           // Writing to textContent (XSS vulnerability)
		"jQuery.html",                                                     // jQuery method for injecting HTML
		"jQuery.append",                                                   // jQuery append method (inserting user input)
		"jQuery.prepend",                                                  // jQuery prepend method (inserting user input)
		"jQuery.html()",
		"jQuery.text()",
		"jQuery.val()",
		"document.querySelector().innerHTML", // Inserting user input into innerHTML
		"document.querySelectorAll().forEach()",
		"console.log", // Logging unencoded data (can be exploited in some cases)
	)

	// Run taint analysis using provided sources and sinks
	results := taint.Check(cg, userControlledValues, xssSinks)
	return results, nil
}
func RunSqlCheck(cg *callgraph.Graph) ([]taint.Result, error) {
	var sqlInjectionSinks = taint.NewSinks(
		// SQL query execution methods
		"(*database/sql.DB).Query",                             // Query execution in SQL (unsafe if user input is not sanitized)
		"(*database/sql.DB).Exec",                              // Executing a SQL query (unsafe if user input is not sanitized)
		"(*database/sql.DB).Prepare",                           // Preparing an SQL statement (unsafe without proper parameterization)
		"(*database/sql.DB).QueryRow",                          // Querying a single row in SQL
		"(*github.com/jinzhu/gorm.DB).Where",                   // GORM ORM's method to build queries (vulnerable to injection if user input is used unsafely)
		"(*github.com/jinzhu/gorm.DB).Exec",                    // Executing a raw query in GORM ORM
		"(*github.com/jinzhu/gorm.DB).Find",                    // Fetching records with user input (potential for SQL injection)
		"(*github.com/jinzhu/gorm.DB).Raw",                     // Executing raw SQL queries in GORM (vulnerable if user input is not sanitized)
		"db.Query",                                             // Generic database query execution
		"db.Exec",                                              // Executing raw queries in database libraries
		"db.Query(q)",                                          // Executing a raw query with user input
		"db.Query(\"SELECT * FROM users WHERE name=?\", name)", // SQL query with parameterized user input
		"(*sql.DB).Query",                                      // Database query method (potentially unsafe if user input is directly inserted)
		"(*sql.DB).Exec",                                       // Executing raw queries (unsafe if using user-controlled data without sanitization)
		"(*sql.DB).QueryRow",                                   // Querying for a single row from the database
		"(*sql.DB).Prepare",                                    // Preparing a SQL query statement (needs parameterization)
		"db.QueryRow",                                          // Querying a single row with user input
		"db.Exec",                                              // Executing SQL queries
		"db.Exec(q)",                                           // Executing a query with user input
		"db.Exec(\"SELECT * FROM users WHERE name=?\", name)", // Example of using parameterized SQL queries
	)

	var sqlInjectionSources = taint.NewSources(
		// User-controlled values from HTTP requests
		"(*net/http.Request).FormValue",       // Form values from HTTP POST requests
		"(*net/http.Request).URL.Query()",     // URL query parameters (e.g., ?id=1)
		"(*net/http.Request).URL.Query().Get", // Specific query parameter (e.g., r.URL.Query().Get("id"))
		"(*net/http.Request).PostForm",        // POST form parameters
		"(*net/http.Request).Header.Get",      // HTTP headers (could contain user-controlled input like User-Agent, etc.)
		"(*net/http.Request).Cookie",          // Cookies that could contain user-controlled data
		"r.FormValue",                         // Form values from a POST request
		"r.URL.Query().Get('paramName')",      // Query parameter from URL (e.g., GET request)
		"os.Args",                             // Command-line arguments
		"os.Args[1]",                          // Specific command-line argument
		"r.Form.Get('paramName')",             // Specific form field
		"r.FormValue('paramName')",            // Specific form field value
		"r.URL.Query().Get('input')",          // Query parameter from URL with user input
		"r.Body",                              // Raw body of the HTTP request (user-controlled data)
		"r.FormValue('formField')",            // A specific form field's value
		"(*net/url.URL).Query",                // Query string of the URL
		"(*net/http.Request).Body",            // HTTP request body
	)

	// Run taint analysis using provided sources and sinks
	results := taint.Check(cg, sqlInjectionSources, sqlInjectionSinks)
	return results, nil
}
