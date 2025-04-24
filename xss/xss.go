package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func loadListFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			filtered = append(filtered, line)
		}
	}
	return filtered, nil
}

func getDynamicSourceAndSinks() (taint.Sources, taint.Sinks, error) {
	sourceList, err := loadListFromFile("sources.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("error reading sources.txt: %v", err)
	}
	sinkList, err := loadListFromFile("sinks.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("error reading sinks.txt: %v", err)
	}
	return taint.NewSources(sourceList...), taint.NewSinks(sinkList...), nil
}

func imports(pass *analysis.Pass, pkgs ...string) bool {
	for _, imp := range pass.Pkg.Imports() {
		for _, pkg := range pkgs {
			if strings.HasSuffix(imp.Path(), pkg) {
				return true
			}
		}
	}
	return false
}

func run(pass *analysis.Pass) (interface{}, error) {
	log.Printf("Running taint analysis...")
	if !imports(pass, "net/http") {
		return nil, nil
	}
	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	mainFn := buildSSA.Pkg.Func("main")
	if mainFn == nil {
		return nil, nil
	}
	cg, err := callgraphutil.NewGraph(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}
	sources, sinks, err := getDynamicSourceAndSinks()
	if err != nil {
		return nil, err
	}
	results := taint.Check(cg, sources, sinks)
	for _, result := range results {
		var escaped bool
		for _, edge := range result.Path {
			for _, arg := range edge.Site.Common().Args {
				taint.WalkSSA(arg, func(v ssa.Value) error {
					call, ok := v.(*ssa.Call)
					if !ok {
						return nil
					}
					if call.Call.Value.String() == "html.EscapeString" {
						escaped = true
						return taint.ErrStopWalk
					}
					return nil
				})
			}
			if escaped {
				break
			}
		}
		if !escaped {
			msg := fmt.Sprintf("Taint flow detected: source=%v -> sink=%v", result.SourceType, result.SinkType)
			pass.Reportf(result.SinkValue.Pos(), msg)
		}
	}
	return nil, nil
}

var Analyzer = &analysis.Analyzer{
	Name:     "xss",
	Doc:      "finds potential XSS issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

func main() {
	baseDir := "./testdata/src"

	absPath, err := filepath.Abs(baseDir)
	if err != nil {
		log.Fatalf("Error getting absolute path: %v", err)
	}
	fmt.Println("Searching in:", absPath)

	subdirs, err := os.ReadDir(absPath)
	if err != nil {
		log.Fatalf("Error reading base directory: %v", err)
	}

	for _, subdir := range subdirs {
		if subdir.IsDir() {
			dirPath := filepath.Join(absPath, subdir.Name())

			cfg := &packages.Config{
				Mode: packages.LoadAllSyntax,
				Dir:  dirPath,
			}

			pkgs, err := packages.Load(cfg, "./...")
			if err != nil {
				log.Printf("Error loading package: %v", err)
				continue
			}
			if packages.PrintErrors(pkgs) > 0 {
				continue
			}

			prog, pkgsMap := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
			prog.Build()

			var mainPkg *ssa.Package
			for _, pkg := range pkgsMap {
				if pkg.Pkg.Name == "main" {
					mainPkg = pkg
					break
				}
			}
			if mainPkg == nil {
				log.Printf("No main package found in %s\n", dirPath)
				continue
			}

			mainFn := mainPkg.Func("main")
			if mainFn == nil {
				log.Printf("No main function found in %s\n", dirPath)
				continue
			}

			cg, err := callgraphutil.NewGraph(mainFn, mainPkg.Members)
			if err != nil {
				log.Printf("Error generating call graph: %v\n", err)
				continue
			}

			fmt.Println("Call Graph Roots:")
			for _, r := range cg.Roots() {
				fmt.Println(" -", r.Func.String())
			}

			fmt.Println("Call Graph Nodes:")
			for fn := range cg.Nodes() {
				fmt.Println(" -", fn.String())
			}

			sources, sinks, err := getDynamicSourceAndSinks()
			if err != nil {
				log.Printf("Failed loading sources/sinks: %v\n", err)
				continue
			}
			results := taint.Check(cg, sources, sinks)

			fmt.Println("Taint Analysis Results:")
			for _, result := range results {
				fmt.Printf("Found taint: %s -> %s\n", result.SourceType, result.SinkType)
				for _, edge := range result.Path {
					fmt.Printf("  %s -> %s\n", edge.Caller, edge.Callee)
				}
			}
			fmt.Println(strings.Repeat("-", 40))
		}
	}
}
