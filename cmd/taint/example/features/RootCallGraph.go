package features

import (
	"bufio"
	"context"

	"golang.org/x/tools/go/callgraph"
)

func RootCallGraph(cg *callgraph.Graph, ctx context.Context, bt *bufio.Writer) error {

	if cg == nil {
		bt.WriteString("no callgraph is loaded\n")
		bt.Flush()
		return nil
	}

	bt.WriteString("Root of this callGraph:=" + cg.Root.String() + "\n")
	bt.Flush()
	return nil
}
