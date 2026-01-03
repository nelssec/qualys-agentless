package export

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type DOTExporter struct {
	g           *graph.SecurityGraph
	showLabels  bool
	clusterByNS bool
}

func NewDOTExporter(g *graph.SecurityGraph) *DOTExporter {
	return &DOTExporter{
		g:           g,
		showLabels:  true,
		clusterByNS: true,
	}
}

func (e *DOTExporter) SetShowLabels(show bool) *DOTExporter {
	e.showLabels = show
	return e
}

func (e *DOTExporter) SetClusterByNamespace(cluster bool) *DOTExporter {
	e.clusterByNS = cluster
	return e
}

func (e *DOTExporter) Export() string {
	var b strings.Builder

	b.WriteString("digraph SecurityGraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=filled];\n")
	b.WriteString("  edge [fontsize=10];\n")
	b.WriteString(fmt.Sprintf("  label=\"%s Security Graph\";\n", e.g.ClusterName))
	b.WriteString("  labelloc=t;\n\n")

	if e.clusterByNS {
		e.exportWithClusters(&b)
	} else {
		e.exportFlat(&b)
	}

	e.exportEdges(&b)

	b.WriteString("}\n")

	return b.String()
}

func (e *DOTExporter) ExportAttackPaths() string {
	var b strings.Builder

	b.WriteString("digraph AttackPaths {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=filled];\n")
	b.WriteString("  edge [fontsize=10, color=red, penwidth=2];\n")
	b.WriteString(fmt.Sprintf("  label=\"%s Attack Paths\";\n", e.g.ClusterName))
	b.WriteString("  labelloc=t;\n\n")

	nodesSeen := make(map[string]bool)

	for _, path := range e.g.AttackPaths {
		for _, step := range path.Steps {
			if !nodesSeen[step.Source] {
				node := e.g.GetNode(step.Source)
				if node != nil {
					b.WriteString(fmt.Sprintf("  %s %s;\n", e.sanitizeID(step.Source), e.getNodeAttrs(*node)))
				}
				nodesSeen[step.Source] = true
			}
			if !nodesSeen[step.Target] {
				node := e.g.GetNode(step.Target)
				if node != nil {
					b.WriteString(fmt.Sprintf("  %s %s;\n", e.sanitizeID(step.Target), e.getNodeAttrs(*node)))
				}
				nodesSeen[step.Target] = true
			}

			label := ""
			if e.showLabels {
				label = fmt.Sprintf(" [label=\"%s\"]", e.escapeLabel(string(step.Type)))
			}
			b.WriteString(fmt.Sprintf("  %s -> %s%s;\n", e.sanitizeID(step.Source), e.sanitizeID(step.Target), label))
		}
	}

	b.WriteString("}\n")

	return b.String()
}

func (e *DOTExporter) exportWithClusters(b *strings.Builder) {
	nodesByNS := make(map[string][]graph.Node)
	var clusterWideNodes []graph.Node

	for _, node := range e.g.Nodes {
		if node.Namespace == "" {
			clusterWideNodes = append(clusterWideNodes, node)
		} else {
			nodesByNS[node.Namespace] = append(nodesByNS[node.Namespace], node)
		}
	}

	for ns, nodes := range nodesByNS {
		b.WriteString(fmt.Sprintf("  subgraph cluster_%s {\n", e.sanitizeID(ns)))
		b.WriteString(fmt.Sprintf("    label=\"Namespace: %s\";\n", ns))
		b.WriteString("    style=filled;\n")
		b.WriteString("    color=lightgrey;\n\n")

		for _, node := range nodes {
			b.WriteString(fmt.Sprintf("    %s %s;\n", e.sanitizeID(node.ID), e.getNodeAttrs(node)))
		}

		b.WriteString("  }\n\n")
	}

	if len(clusterWideNodes) > 0 {
		b.WriteString("  subgraph cluster_global {\n")
		b.WriteString("    label=\"Cluster-Wide Resources\";\n")
		b.WriteString("    style=filled;\n")
		b.WriteString("    color=lightyellow;\n\n")

		for _, node := range clusterWideNodes {
			b.WriteString(fmt.Sprintf("    %s %s;\n", e.sanitizeID(node.ID), e.getNodeAttrs(node)))
		}

		b.WriteString("  }\n\n")
	}
}

func (e *DOTExporter) exportFlat(b *strings.Builder) {
	for _, node := range e.g.Nodes {
		b.WriteString(fmt.Sprintf("  %s %s;\n", e.sanitizeID(node.ID), e.getNodeAttrs(node)))
	}
	b.WriteString("\n")
}

func (e *DOTExporter) exportEdges(b *strings.Builder) {
	for _, edge := range e.g.Edges {
		attrs := e.getEdgeAttrs(edge)
		b.WriteString(fmt.Sprintf("  %s -> %s%s;\n", e.sanitizeID(edge.Source), e.sanitizeID(edge.Target), attrs))
	}
}

func (e *DOTExporter) getNodeAttrs(node graph.Node) string {
	color := e.getRiskColor(node.Risk)
	shape := e.getNodeShape(node.Type)
	label := e.escapeLabel(node.Name)

	if node.Namespace != "" {
		label = fmt.Sprintf("%s\\n(%s)", label, node.Type)
	}

	return fmt.Sprintf("[label=\"%s\", fillcolor=\"%s\", shape=%s]", label, color, shape)
}

func (e *DOTExporter) getEdgeAttrs(edge graph.Edge) string {
	var attrs []string

	if e.showLabels && edge.Label != "" {
		attrs = append(attrs, fmt.Sprintf("label=\"%s\"", e.escapeLabel(edge.Label)))
	}

	color := "black"
	penwidth := "1"
	switch edge.Risk {
	case graph.RiskCritical:
		color = "red"
		penwidth = "3"
	case graph.RiskHigh:
		color = "orange"
		penwidth = "2"
	case graph.RiskMedium:
		color = "yellow4"
	}

	if edge.Type == graph.EdgeEscalatesTo || edge.Type == graph.EdgeEscapesTo {
		color = "red"
		penwidth = "2"
		attrs = append(attrs, "style=dashed")
	}

	attrs = append(attrs, fmt.Sprintf("color=\"%s\"", color))
	attrs = append(attrs, fmt.Sprintf("penwidth=%s", penwidth))

	if len(attrs) > 0 {
		return " [" + strings.Join(attrs, ", ") + "]"
	}
	return ""
}

func (e *DOTExporter) getRiskColor(risk graph.RiskLevel) string {
	switch risk {
	case graph.RiskCritical:
		return "#ff0000"
	case graph.RiskHigh:
		return "#ff6600"
	case graph.RiskMedium:
		return "#ffcc00"
	case graph.RiskLow:
		return "#99ff99"
	default:
		return "#cccccc"
	}
}

func (e *DOTExporter) getNodeShape(nodeType graph.NodeType) string {
	switch nodeType {
	case graph.NodePod:
		return "box"
	case graph.NodeServiceAccount:
		return "ellipse"
	case graph.NodeRole, graph.NodeClusterRole:
		return "diamond"
	case graph.NodeSecret:
		return "octagon"
	case graph.NodeService:
		return "hexagon"
	case graph.NodeIngress:
		return "trapezium"
	case graph.NodeNode:
		return "box3d"
	case graph.NodeNamespace:
		return "folder"
	case graph.NodeExternal:
		return "doubleoctagon"
	default:
		return "box"
	}
}

func (e *DOTExporter) sanitizeID(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, ".", "_")
	id = strings.ReplaceAll(id, ":", "_")
	return "n_" + id
}

func (e *DOTExporter) escapeLabel(s string) string {
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
