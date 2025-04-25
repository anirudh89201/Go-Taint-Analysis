package features

import (
	"bufio"
	"context"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/taint"

	"golang.org/x/tools/go/callgraph"
)

var styleFaint = lipgloss.NewStyle().Faint(true)
var styleNumber = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69"))

func highlightNode(node string) string {
	// Split the node string on the colon.
	parts := strings.Split(node, ":")

	// Get the node ID.
	nodeID := parts[0]

	// Highlight the node ID.
	nodeID = styleNumber.Render(nodeID)

	// Get the rest of the node string.
	nodeStr := strings.Join(parts[1:], ":")

	// Return the highlighted node.
	return nodeID + ":" + nodeStr
}
func CheckSourceAndSink(source string, sink string, cg *callgraph.Graph, ctx context.Context, bt *bufio.Writer) error {
	if cg == nil {
		bt.WriteString("no callgraph is loaded\n")
		bt.Flush()
		return nil
	}
	results := taint.Check(cg, taint.NewSources(source), taint.NewSinks(sink))

	var resultsStr strings.Builder

	for _, result := range results {
		resultPathStr := result.Path.String()

		parts := strings.Split(resultPathStr, " → ")

		for i, part := range parts {
			parts[i] = highlightNode(part)
		}

		resultPathStr = strings.Join(parts, styleFaint.Render(" → "))

		resultsStr.WriteString(resultPathStr + "\n")
	}

	bt.WriteString(resultsStr.String())
	bt.Flush()
	return nil
}
