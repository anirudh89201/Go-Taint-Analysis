package features

import (
	"bufio"
	"context"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
)

func PrintCallGraph(ctx context.Context, bt *bufio.Writer, cg *callgraph.Graph) error {
	if cg == nil {
		bt.WriteString("no callgraph is loaded\n")
		bt.Flush()
		return nil
	}
	styleFaint := lipgloss.NewStyle().Faint(true)
	cgStr := strings.ReplaceAll(callgraphutil.GraphString(cg), "→", styleFaint.Render("→"))
	bt.WriteString(cgStr)
	bt.Flush()
	return nil
}
