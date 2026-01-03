package graph

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskInfo     RiskLevel = "info"
)

type NodeType string

const (
	NodePod              NodeType = "pod"
	NodeServiceAccount   NodeType = "serviceaccount"
	NodeRole             NodeType = "role"
	NodeClusterRole      NodeType = "clusterrole"
	NodeRoleBinding      NodeType = "rolebinding"
	NodeClusterRoleBinding NodeType = "clusterrolebinding"
	NodeSecret           NodeType = "secret"
	NodeConfigMap        NodeType = "configmap"
	NodeService          NodeType = "service"
	NodeIngress          NodeType = "ingress"
	NodeNamespace        NodeType = "namespace"
	NodeNode             NodeType = "node"
	NodeNetworkPolicy    NodeType = "networkpolicy"
	NodePersistentVolume NodeType = "persistentvolume"
	NodeExternal         NodeType = "external" // Internet, cloud metadata, etc.
)

type EdgeType string

const (
	// Identity & Access
	EdgeUses           EdgeType = "uses"            // Pod uses ServiceAccount
	EdgeBindsTo        EdgeType = "binds_to"        // RoleBinding binds SA to Role
	EdgeGrants         EdgeType = "grants"          // Role grants permissions
	EdgeCanAccess      EdgeType = "can_access"      // SA can access resource
	EdgeCanExec        EdgeType = "can_exec"        // SA can exec into pods
	EdgeCanCreate      EdgeType = "can_create"      // SA can create resources
	EdgeCanDelete      EdgeType = "can_delete"      // SA can delete resources
	EdgeEscalatesTo    EdgeType = "escalates_to"    // Privilege escalation path

	// Data Access
	EdgeMounts         EdgeType = "mounts"          // Pod mounts Secret/ConfigMap/Volume
	EdgeReferences     EdgeType = "references"      // Pod references Secret in env
	EdgeExposes        EdgeType = "exposes"         // Service exposes Pod

	// Network
	EdgeExposedTo      EdgeType = "exposed_to"      // Pod/Service exposed to external
	EdgeCanReach       EdgeType = "can_reach"       // Network path exists
	EdgeBlocks         EdgeType = "blocks"          // NetworkPolicy blocks traffic

	// Risk Relationships
	EdgeCompromises    EdgeType = "compromises"     // Attack leads to compromise
	EdgeExfiltratesTo  EdgeType = "exfiltrates_to"  // Data exfiltration path
	EdgeEscapesTo      EdgeType = "escapes_to"      // Container escape to node
)

type Node struct {
	ID         string            `json:"id"`
	Type       NodeType          `json:"type"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace,omitempty"`
	Risk       RiskLevel         `json:"risk"`
	RiskScore  int               `json:"riskScore"` // 0-100
	Labels     map[string]string `json:"labels,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
	Findings   []string          `json:"findings,omitempty"` // Security findings for this node
}

type Edge struct {
	ID         string         `json:"id"`
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Type       EdgeType       `json:"type"`
	Risk       RiskLevel      `json:"risk,omitempty"`
	RiskScore  int            `json:"riskScore,omitempty"`
	Label      string         `json:"label,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	Bidirectional bool        `json:"bidirectional,omitempty"`
}

type AttackPath struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Risk        RiskLevel `json:"risk"`
	RiskScore   int       `json:"riskScore"`
	Steps       []Edge    `json:"steps"`
	StartNode   string    `json:"startNode"`
	EndNode     string    `json:"endNode"`
	Mitigations []string  `json:"mitigations,omitempty"`
}

type SecurityGraph struct {
	ClusterName  string            `json:"clusterName"`
	GeneratedAt  string            `json:"generatedAt"`
	Nodes        []Node            `json:"nodes"`
	Edges        []Edge            `json:"edges"`
	AttackPaths  []AttackPath      `json:"attackPaths,omitempty"`
	Summary      GraphSummary      `json:"summary"`
	nodeIndex    map[string]*Node  `json:"-"` // internal index
	edgeIndex    map[string]*Edge  `json:"-"` // internal index
}

type GraphSummary struct {
	TotalNodes           int            `json:"totalNodes"`
	TotalEdges           int            `json:"totalEdges"`
	TotalAttackPaths     int            `json:"totalAttackPaths"`
	CriticalPaths        int            `json:"criticalPaths"`
	HighRiskNodes        int            `json:"highRiskNodes"`
	ExternalExposures    int            `json:"externalExposures"`
	PrivilegeEscalations int            `json:"privilegeEscalations"`
	ContainerEscapes     int            `json:"containerEscapes"`
	DataExfiltrationRisks int           `json:"dataExfiltrationRisks"`
	NodesByType          map[string]int `json:"nodesByType"`
	EdgesByType          map[string]int `json:"edgesByType"`
	RiskDistribution     map[string]int `json:"riskDistribution"`
}

func NewSecurityGraph(clusterName string) *SecurityGraph {
	return &SecurityGraph{
		ClusterName: clusterName,
		Nodes:       make([]Node, 0),
		Edges:       make([]Edge, 0),
		AttackPaths: make([]AttackPath, 0),
		nodeIndex:   make(map[string]*Node),
		edgeIndex:   make(map[string]*Edge),
		Summary: GraphSummary{
			NodesByType:      make(map[string]int),
			EdgesByType:      make(map[string]int),
			RiskDistribution: make(map[string]int),
		},
	}
}

func (g *SecurityGraph) AddNode(node Node) {
	if _, exists := g.nodeIndex[node.ID]; exists {
		return // Node already exists
	}
	g.Nodes = append(g.Nodes, node)
	g.nodeIndex[node.ID] = &g.Nodes[len(g.Nodes)-1]
	g.Summary.TotalNodes++
	g.Summary.NodesByType[string(node.Type)]++
	g.Summary.RiskDistribution[string(node.Risk)]++
	if node.Risk == RiskHigh || node.Risk == RiskCritical {
		g.Summary.HighRiskNodes++
	}
}

func (g *SecurityGraph) AddEdge(edge Edge) {
	if edge.ID == "" {
		edge.ID = edge.Source + "->" + string(edge.Type) + "->" + edge.Target
	}
	if _, exists := g.edgeIndex[edge.ID]; exists {
		return
	}
	if _, srcExists := g.nodeIndex[edge.Source]; !srcExists {
		return
	}
	if _, tgtExists := g.nodeIndex[edge.Target]; !tgtExists {
		return
	}
	g.Edges = append(g.Edges, edge)
	g.edgeIndex[edge.ID] = &g.Edges[len(g.Edges)-1]
	g.Summary.TotalEdges++
	g.Summary.EdgesByType[string(edge.Type)]++
}

func (g *SecurityGraph) AddAttackPath(path AttackPath) {
	g.AttackPaths = append(g.AttackPaths, path)
	g.Summary.TotalAttackPaths++
	if path.Risk == RiskCritical {
		g.Summary.CriticalPaths++
	}
}

func (g *SecurityGraph) GetNode(id string) *Node {
	return g.nodeIndex[id]
}

func (g *SecurityGraph) GetOutgoingEdges(nodeID string) []Edge {
	var edges []Edge
	for _, e := range g.Edges {
		if e.Source == nodeID {
			edges = append(edges, e)
		}
	}
	return edges
}

func (g *SecurityGraph) GetIncomingEdges(nodeID string) []Edge {
	var edges []Edge
	for _, e := range g.Edges {
		if e.Target == nodeID {
			edges = append(edges, e)
		}
	}
	return edges
}

func (g *SecurityGraph) FindPaths(startID, endID string, maxDepth int) [][]Edge {
	var paths [][]Edge
	type state struct {
		nodeID string
		path   []Edge
	}

	queue := []state{{nodeID: startID, path: nil}}
	visited := make(map[string]bool)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxDepth {
			continue
		}

		if current.nodeID == endID && len(current.path) > 0 {
			paths = append(paths, current.path)
			continue
		}

		for _, edge := range g.GetOutgoingEdges(current.nodeID) {
			pathKey := current.nodeID + ":" + edge.Target
			if visited[pathKey] {
				continue
			}
			visited[pathKey] = true

			newPath := make([]Edge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			queue = append(queue, state{nodeID: edge.Target, path: newPath})
		}
	}

	return paths
}

func (g *SecurityGraph) CalculateBlastRadius(nodeID string, maxDepth int) int {
	reachable := make(map[string]bool)
	queue := []string{nodeID}
	depth := 0

	for len(queue) > 0 && depth < maxDepth {
		nextQueue := []string{}
		for _, id := range queue {
			for _, edge := range g.GetOutgoingEdges(id) {
				if !reachable[edge.Target] {
					reachable[edge.Target] = true
					nextQueue = append(nextQueue, edge.Target)
				}
			}
		}
		queue = nextQueue
		depth++
	}

	return len(reachable)
}
