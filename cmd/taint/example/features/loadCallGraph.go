package features

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func LoadCallGraph(ctx context.Context, inputPath string, pattern string) (*callgraph.Graph, error) {
	if pattern == "" {
		pattern = "./..."
	}

	// Ensure inputPath is valid
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory %q does not exist", inputPath)
	}

	// Configure package loading
	cfg := &packages.Config{
		Context: ctx,
		Mode: packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedModule |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Dir:   inputPath,
		Env:   os.Environ(),
		Tests: false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
		},
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("package loading error: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, errors.New("error(s) found in loaded packages")
	}

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) == 0 {
		return nil, errors.New("no main package found")
	}

	mainFn, ok := mainPkgs[0].Members["main"].(*ssa.Function)
	if !ok || mainFn == nil {
		return nil, errors.New("main function not found")
	}

	var srcFns []*ssa.Function
	for _, pkg := range ssaPkgs {
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok && fn.Object() != nil && fn.Object().Name() != "_" {
				addAnonFunctions(fn, &srcFns)
			}
		}
	}

	graph, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		return nil, fmt.Errorf("callgraph generation failed: %w", err)
	}

	return graph, nil
}

func addAnonFunctions(fn *ssa.Function, acc *[]*ssa.Function) {
	*acc = append(*acc, fn)
	for _, anon := range fn.AnonFuncs {
		addAnonFunctions(anon, acc)
	}
}
