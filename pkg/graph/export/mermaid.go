package export

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type MermaidExporter struct {
	g          *graph.SecurityGraph
	direction  string
	showStyles bool
}

func NewMermaidExporter(g *graph.SecurityGraph) *MermaidExporter {
	return &MermaidExporter{
		g:          g,
		direction:  "LR",
		showStyles: true,
	}
}

func (e *MermaidExporter) SetDirection(dir string) *MermaidExporter {
	e.direction = dir
	return e
}

func (e *MermaidExporter) Export() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("graph %s\n", e.direction))

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
		b.WriteString(fmt.Sprintf("  subgraph %s[\"Namespace: %s\"]\n", e.sanitizeID("ns_"+ns), ns))
		for _, node := range nodes {
			b.WriteString(fmt.Sprintf("    %s\n", e.formatNode(node)))
		}
		b.WriteString("  end\n")
	}

	if len(clusterWideNodes) > 0 {
		b.WriteString("  subgraph cluster_wide[\"Cluster-Wide\"]\n")
		for _, node := range clusterWideNodes {
			b.WriteString(fmt.Sprintf("    %s\n", e.formatNode(node)))
		}
		b.WriteString("  end\n")
	}

	b.WriteString("\n")

	for _, edge := range e.g.Edges {
		b.WriteString(fmt.Sprintf("  %s\n", e.formatEdge(edge)))
	}

	if e.showStyles {
		b.WriteString("\n")
		b.WriteString(e.generateStyles())
	}

	return b.String()
}

func (e *MermaidExporter) ExportAttackPaths() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("graph %s\n", e.direction))

	nodesSeen := make(map[string]bool)

	for i, path := range e.g.AttackPaths {
		b.WriteString(fmt.Sprintf("  subgraph path%d[\"%s\"]\n", i, path.Name))

		for _, step := range path.Steps {
			if !nodesSeen[step.Source] {
				node := e.g.GetNode(step.Source)
				if node != nil {
					b.WriteString(fmt.Sprintf("    %s\n", e.formatNode(*node)))
				}
				nodesSeen[step.Source] = true
			}
			if !nodesSeen[step.Target] {
				node := e.g.GetNode(step.Target)
				if node != nil {
					b.WriteString(fmt.Sprintf("    %s\n", e.formatNode(*node)))
				}
				nodesSeen[step.Target] = true
			}
		}

		b.WriteString("  end\n")
	}

	b.WriteString("\n")

	for _, path := range e.g.AttackPaths {
		for _, step := range path.Steps {
			arrow := "-->"
			if step.Type == graph.EdgeEscalatesTo || step.Type == graph.EdgeEscapesTo {
				arrow = "==>"
			}
			label := string(step.Type)
			b.WriteString(fmt.Sprintf("  %s %s|%s| %s\n", e.sanitizeID(step.Source), arrow, label, e.sanitizeID(step.Target)))
		}
	}

	if e.showStyles {
		b.WriteString("\n")
		b.WriteString(e.generateStyles())
	}

	return b.String()
}

func (e *MermaidExporter) ExportExposureFlow() string {
	var b strings.Builder

	b.WriteString("graph LR\n")

	b.WriteString("  Internet((Internet))\n")

	for _, node := range e.g.Nodes {
		if node.Type == graph.NodeIngress || node.Type == graph.NodeService {
			b.WriteString(fmt.Sprintf("  %s\n", e.formatNode(node)))
		}
	}

	for _, edge := range e.g.Edges {
		if edge.Type == graph.EdgeExposedTo || edge.Type == graph.EdgeExposes {
			b.WriteString(fmt.Sprintf("  %s\n", e.formatEdge(edge)))
		}
	}

	b.WriteString("\n  style Internet fill:#ff0000,stroke:#000,stroke-width:2px\n")

	return b.String()
}

func (e *MermaidExporter) formatNode(node graph.Node) string {
	id := e.sanitizeID(node.ID)
	label := e.escapeLabel(node.Name)

	shape := e.getNodeShape(node.Type)
	return fmt.Sprintf("%s%s", id, shape(label))
}

func (e *MermaidExporter) formatEdge(edge graph.Edge) string {
	source := e.sanitizeID(edge.Source)
	target := e.sanitizeID(edge.Target)

	arrow := "-->"
	switch edge.Risk {
	case graph.RiskCritical:
		arrow = "==>"
	case graph.RiskHigh:
		arrow = "--->"
	}

	if edge.Type == graph.EdgeEscalatesTo || edge.Type == graph.EdgeEscapesTo {
		arrow = "==>"
	}

	label := string(edge.Type)
	if edge.Label != "" {
		label = edge.Label
	}

	return fmt.Sprintf("%s %s|%s| %s", source, arrow, label, target)
}

func (e *MermaidExporter) getNodeShape(nodeType graph.NodeType) func(string) string {
	switch nodeType {
	case graph.NodePod:
		return func(label string) string { return fmt.Sprintf("[%s]", label) }
	case graph.NodeServiceAccount:
		return func(label string) string { return fmt.Sprintf("([%s])", label) }
	case graph.NodeRole, graph.NodeClusterRole:
		return func(label string) string { return fmt.Sprintf("{%s}", label) }
	case graph.NodeSecret:
		return func(label string) string { return fmt.Sprintf("{{%s}}", label) }
	case graph.NodeService:
		return func(label string) string { return fmt.Sprintf("[/%s/]", label) }
	case graph.NodeIngress:
		return func(label string) string { return fmt.Sprintf("[\\%s\\]", label) }
	case graph.NodeNode:
		return func(label string) string { return fmt.Sprintf("[(%s)]", label) }
	case graph.NodeNamespace:
		return func(label string) string { return fmt.Sprintf(">%s]", label) }
	case graph.NodeExternal:
		return func(label string) string { return fmt.Sprintf("((%s))", label) }
	default:
		return func(label string) string { return fmt.Sprintf("[%s]", label) }
	}
}

func (e *MermaidExporter) generateStyles() string {
	var b strings.Builder

	criticalNodes := []string{}
	highNodes := []string{}
	mediumNodes := []string{}
	lowNodes := []string{}

	for _, node := range e.g.Nodes {
		id := e.sanitizeID(node.ID)
		switch node.Risk {
		case graph.RiskCritical:
			criticalNodes = append(criticalNodes, id)
		case graph.RiskHigh:
			highNodes = append(highNodes, id)
		case graph.RiskMedium:
			mediumNodes = append(mediumNodes, id)
		case graph.RiskLow:
			lowNodes = append(lowNodes, id)
		}
	}

	if len(criticalNodes) > 0 {
		b.WriteString("  classDef critical fill:#ff0000,stroke:#000,stroke-width:2px,color:#fff\n")
		b.WriteString(fmt.Sprintf("  class %s critical\n", strings.Join(criticalNodes, ",")))
	}
	if len(highNodes) > 0 {
		b.WriteString("  classDef high fill:#ff6600,stroke:#000,stroke-width:2px\n")
		b.WriteString(fmt.Sprintf("  class %s high\n", strings.Join(highNodes, ",")))
	}
	if len(mediumNodes) > 0 {
		b.WriteString("  classDef medium fill:#ffcc00,stroke:#000\n")
		b.WriteString(fmt.Sprintf("  class %s medium\n", strings.Join(mediumNodes, ",")))
	}
	if len(lowNodes) > 0 {
		b.WriteString("  classDef low fill:#99ff99,stroke:#000\n")
		b.WriteString(fmt.Sprintf("  class %s low\n", strings.Join(lowNodes, ",")))
	}

	return b.String()
}

func (e *MermaidExporter) sanitizeID(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, ".", "_")
	id = strings.ReplaceAll(id, ":", "_")
	return id
}

func (e *MermaidExporter) escapeLabel(s string) string {
	s = strings.ReplaceAll(s, "\"", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
