package analyzers

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type EscalationAnalyzer struct {
	g *graph.SecurityGraph
}

func NewEscalationAnalyzer(g *graph.SecurityGraph) *EscalationAnalyzer {
	return &EscalationAnalyzer{g: g}
}

type EscalationPath struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	StartNode   *graph.Node   `json:"startNode"`
	EndNode     *graph.Node   `json:"endNode"`
	Steps       []PathStep    `json:"steps"`
	RiskScore   int           `json:"riskScore"`
	Mitigations []string      `json:"mitigations"`
}

type PathStep struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

func (a *EscalationAnalyzer) Analyze() []EscalationPath {
	var paths []EscalationPath

	// Find all entry points (pods, compromised SA, etc.)
	entryPoints := a.findEntryPoints()

	// Find all high-value targets
	targets := a.findHighValueTargets()

	// Find paths from entry points to targets
	for _, entry := range entryPoints {
		for _, target := range targets {
			foundPaths := a.g.FindPaths(entry.ID, target.ID, 6)
			for i, edgePath := range foundPaths {
				if path := a.buildEscalationPath(entry, target, edgePath, i); path != nil {
					paths = append(paths, *path)
				}
			}
		}
	}

	// Also find SA-to-cluster-admin paths
	saPaths := a.findSAEscalationPaths()
	paths = append(paths, saPaths...)

	return paths
}

func (a *EscalationAnalyzer) findEntryPoints() []*graph.Node {
	var entries []*graph.Node

	for i := range a.g.Nodes {
		node := &a.g.Nodes[i]

		// Internet-exposed pods/services are entry points
		if node.Type == graph.NodePod || node.Type == graph.NodeService {
			// Check if exposed
			for _, edge := range a.g.GetIncomingEdges(node.ID) {
				if edge.Type == graph.EdgeExposedTo {
					entries = append(entries, node)
					break
				}
			}
		}

		// High-risk pods are potential entry points
		if node.Type == graph.NodePod && (node.Risk == graph.RiskHigh || node.Risk == graph.RiskCritical) {
			entries = append(entries, node)
		}
	}

	return entries
}

func (a *EscalationAnalyzer) findHighValueTargets() []*graph.Node {
	var targets []*graph.Node

	for i := range a.g.Nodes {
		node := &a.g.Nodes[i]

		// cluster-admin role is a high-value target
		if node.Type == graph.NodeClusterRole && node.Name == "cluster-admin" {
			targets = append(targets, node)
		}

		// Nodes are high-value targets (container escape)
		if node.Type == graph.NodeNode {
			targets = append(targets, node)
		}

		// Cloud metadata is high-value
		if node.Type == graph.NodeExternal && node.Name == "Cloud Metadata Service" {
			targets = append(targets, node)
		}

		// Secrets containing credentials
		if node.Type == graph.NodeSecret && node.Risk >= graph.RiskMedium {
			targets = append(targets, node)
		}
	}

	return targets
}

func (a *EscalationAnalyzer) buildEscalationPath(start, end *graph.Node, edges []graph.Edge, idx int) *EscalationPath {
	if len(edges) == 0 {
		return nil
	}

	steps := make([]PathStep, len(edges))
	totalRisk := 0

	for i, edge := range edges {
		steps[i] = PathStep{
			From:        edge.Source,
			To:          edge.Target,
			Action:      string(edge.Type),
			Description: a.describeStep(edge),
		}
		totalRisk += riskToScore(edge.Risk)
	}

	return &EscalationPath{
		ID:          fmt.Sprintf("escalation-%s-%s-%d", start.ID, end.ID, idx),
		Name:        fmt.Sprintf("%s to %s", start.Name, end.Name),
		Description: a.describeEscalationPath(start, end, steps),
		StartNode:   start,
		EndNode:     end,
		Steps:       steps,
		RiskScore:   totalRisk / len(edges),
		Mitigations: a.suggestMitigations(steps),
	}
}

func (a *EscalationAnalyzer) findSAEscalationPaths() []EscalationPath {
	var paths []EscalationPath

	// Find service accounts that can create privileged pods
	for i := range a.g.Nodes {
		node := &a.g.Nodes[i]
		if node.Type != graph.NodeServiceAccount {
			continue
		}

		// Check outgoing edges for escalation capabilities
		for _, edge := range a.g.GetOutgoingEdges(node.ID) {
			if edge.Type == graph.EdgeEscalatesTo {
				targetNode := a.g.GetNode(edge.Target)
				if targetNode == nil {
					continue
				}

				path := EscalationPath{
					ID:          fmt.Sprintf("sa-escalation-%s", node.ID),
					Name:        fmt.Sprintf("SA %s/%s can escalate privileges", node.Namespace, node.Name),
					Description: fmt.Sprintf("Service account %s in namespace %s has permissions that allow privilege escalation to %s", node.Name, node.Namespace, targetNode.Name),
					StartNode:   node,
					EndNode:     targetNode,
					Steps: []PathStep{
						{
							From:        node.ID,
							To:          edge.Target,
							Action:      "escalates_to",
							Description: "Can create bindings or impersonate privileged roles",
						},
					},
					RiskScore: 90,
					Mitigations: []string{
						"Remove bind/escalate/impersonate verbs from role",
						"Use PodSecurityAdmission to prevent privileged pod creation",
						"Implement admission control (OPA Gatekeeper/Kyverno)",
					},
				}
				paths = append(paths, path)
			}
		}
	}

	return paths
}

func (a *EscalationAnalyzer) describeStep(edge graph.Edge) string {
	switch edge.Type {
	case graph.EdgeUses:
		return fmt.Sprintf("Uses %s", edge.Target)
	case graph.EdgeBindsTo:
		return fmt.Sprintf("Bound to %s", edge.Target)
	case graph.EdgeMounts:
		return fmt.Sprintf("Mounts %s", edge.Target)
	case graph.EdgeCanExec:
		return fmt.Sprintf("Can exec into %s", edge.Target)
	case graph.EdgeEscalatesTo:
		return fmt.Sprintf("Can escalate to %s", edge.Target)
	case graph.EdgeEscapesTo:
		return fmt.Sprintf("Can escape to %s via %s", edge.Target, edge.Label)
	case graph.EdgeExposedTo:
		return fmt.Sprintf("Exposed via %s", edge.Label)
	default:
		return edge.Label
	}
}

func (a *EscalationAnalyzer) describeEscalationPath(start, end *graph.Node, steps []PathStep) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Attack path from %s (%s) to %s (%s):\n", start.Name, start.Type, end.Name, end.Type))

	for i, step := range steps {
		desc.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step.Description))
	}

	return desc.String()
}

func (a *EscalationAnalyzer) suggestMitigations(steps []PathStep) []string {
	mitigations := make(map[string]bool)

	for _, step := range steps {
		switch step.Action {
		case "uses":
			mitigations["Disable automountServiceAccountToken on pods"] = true
		case "binds_to":
			mitigations["Review and minimize RBAC role bindings"] = true
		case "escalates_to":
			mitigations["Remove bind/escalate/impersonate permissions"] = true
			mitigations["Implement PodSecurityAdmission"] = true
		case "escapes_to":
			mitigations["Remove privileged container permissions"] = true
			mitigations["Remove hostPID/hostNetwork/hostIPC"] = true
			mitigations["Remove docker.sock mounts"] = true
		case "can_exec":
			mitigations["Remove pods/exec permissions from roles"] = true
		case "mounts":
			mitigations["Use sealed-secrets or external-secrets"] = true
		}
	}

	result := make([]string, 0, len(mitigations))
	for m := range mitigations {
		result = append(result, m)
	}
	return result
}

func riskToScore(risk graph.RiskLevel) int {
	switch risk {
	case graph.RiskCritical:
		return 95
	case graph.RiskHigh:
		return 75
	case graph.RiskMedium:
		return 50
	case graph.RiskLow:
		return 25
	default:
		return 10
	}
}
