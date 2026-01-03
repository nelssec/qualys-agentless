package export

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type TopologyExporter struct {
	g           *graph.SecurityGraph
	remediation map[string]*RemediationInfo
}

// RemediationInfo contains control remediation details
type RemediationInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Section     string `json:"section"`
	Remediation string `json:"remediation"`
	Framework   string `json:"framework"`
}

type TopoNode struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Namespace  string            `json:"namespace,omitempty"`
	Risk       string            `json:"risk"`
	RiskScore  int               `json:"riskScore"`
	Layer      int               `json:"layer"`
	Findings   []string          `json:"findings,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
}

type TopoLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Risk   string `json:"risk"`
}

type TopoGraph struct {
	Nodes       []TopoNode `json:"nodes"`
	Links       []TopoLink `json:"links"`
	ClusterName string     `json:"clusterName"`
}

func NewTopologyExporter(g *graph.SecurityGraph) *TopologyExporter {
	return &TopologyExporter{g: g, remediation: make(map[string]*RemediationInfo)}
}

// SetRemediation sets the remediation lookup from compliance controls
func (e *TopologyExporter) SetRemediation(remediation map[string]*RemediationInfo) {
	e.remediation = remediation
}

func (e *TopologyExporter) getLayer(nodeType graph.NodeType) int {
	switch nodeType {
	case graph.NodeExternal:
		return 0
	case graph.NodeIngress:
		return 1
	case graph.NodeService:
		return 2
	case graph.NodePod:
		return 3
	case graph.NodeServiceAccount:
		return 4
	case graph.NodeSecret:
		return 5
	case graph.NodeNode:
		return 6
	case graph.NodeRole, graph.NodeClusterRole:
		return 7
	case graph.NodeRoleBinding, graph.NodeClusterRoleBinding:
		return 8
	default:
		return 9
	}
}

func (e *TopologyExporter) isAttackSurfaceNode(node graph.Node) bool {
	switch node.Type {
	case graph.NodePod, graph.NodeService, graph.NodeIngress, graph.NodeSecret,
		graph.NodeServiceAccount, graph.NodeNode:
		return true
	case graph.NodeExternal:
		if node.ID == "external/internet" {
			return true
		}
		return false
	}
	return false
}

func (e *TopologyExporter) buildFlowGraph() TopoGraph {
	connectedIDs := make(map[string]bool)
	for _, edge := range e.g.Edges {
		connectedIDs[edge.Source] = true
		connectedIDs[edge.Target] = true
	}

	nodes := make([]TopoNode, 0)
	nodeIndex := make(map[string]bool)

	hasExternalExposure := false
	exposedEndpoints := []string{}

	for _, node := range e.g.Nodes {
		if !connectedIDs[node.ID] {
			continue
		}
		if !e.isAttackSurfaceNode(node) {
			continue
		}
		if nodeIndex[node.ID] {
			continue
		}
		nodeIndex[node.ID] = true

		if node.Type == graph.NodeIngress {
			hasExternalExposure = true
			exposedEndpoints = append(exposedEndpoints, node.ID)
		}
		if node.Type == graph.NodeService {
			hasExternalExposure = true
			exposedEndpoints = append(exposedEndpoints, node.ID)
		}

		nodes = append(nodes, TopoNode{
			ID:         node.ID,
			Name:       node.Name,
			Type:       string(node.Type),
			Namespace:  node.Namespace,
			Risk:       string(node.Risk),
			RiskScore:  node.RiskScore,
			Layer:      e.getLayer(node.Type),
			Findings:   node.Findings,
			Labels:     node.Labels,
			Properties: node.Properties,
		})
	}

	if hasExternalExposure && !nodeIndex["external/internet"] {
		nodes = append([]TopoNode{{
			ID:        "external/internet",
			Name:      "Internet",
			Type:      "external",
			Risk:      "critical",
			RiskScore: 100,
			Layer:     0,
			Findings:  []string{"External attack surface"},
		}}, nodes...)
		nodeIndex["external/internet"] = true
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Layer != nodes[j].Layer {
			return nodes[i].Layer < nodes[j].Layer
		}
		return nodes[i].Name < nodes[j].Name
	})

	links := make([]TopoLink, 0)
	linkIndex := make(map[string]bool)

	for _, endpoint := range exposedEndpoints {
		key := "external/internet->" + endpoint
		if !linkIndex[key] {
			linkIndex[key] = true
			links = append(links, TopoLink{
				Source: "external/internet",
				Target: endpoint,
				Type:   "exposes",
				Risk:   "critical",
			})
		}
	}

	for _, edge := range e.g.Edges {
		if !nodeIndex[edge.Source] || !nodeIndex[edge.Target] {
			continue
		}
		key := edge.Source + "->" + edge.Target
		if linkIndex[key] {
			continue
		}
		linkIndex[key] = true
		links = append(links, TopoLink{
			Source: edge.Source,
			Target: edge.Target,
			Type:   string(edge.Type),
			Risk:   string(edge.Risk),
		})
	}

	return TopoGraph{
		Nodes:       nodes,
		Links:       links,
		ClusterName: e.g.ClusterName,
	}
}

func (e *TopologyExporter) ExportHTML() string {
	topoGraph := e.buildFlowGraph()
	jsonData, _ := json.Marshal(topoGraph)

	remediationData, _ := json.Marshal(e.remediation)

	criticalCount := 0
	highCount := 0
	podCount := 0
	serviceCount := 0
	for _, n := range topoGraph.Nodes {
		if n.Risk == "critical" {
			criticalCount++
		} else if n.Risk == "high" {
			highCount++
		}
		if n.Type == "pod" {
			podCount++
		}
		if n.Type == "service" || n.Type == "ingress" {
			serviceCount++
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s - Attack Surface</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; overflow: hidden; }
    #container { display: flex; height: 100vh; }
    #sidebar { width: 300px; background: linear-gradient(180deg, #1e293b 0%%, #0f172a 100%%); border-right: 1px solid #334155; padding: 24px; overflow-y: auto; }
    #graph { flex: 1; position: relative; background: radial-gradient(ellipse at center, #1e293b 0%%, #0f172a 70%%); }
    svg { width: 100%%; height: 100%%; }
    .header { margin-bottom: 32px; }
    .header h1 { font-size: 18px; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; }
    .header .subtitle { font-size: 13px; color: #64748b; }
    .section { margin-bottom: 28px; }
    .section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .section-title::before { content: ''; width: 3px; height: 12px; background: #6366f1; border-radius: 2px; }
    .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .stat { background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 12px; padding: 16px; transition: all 0.2s; }
    .stat:hover { border-color: #6366f1; transform: translateY(-2px); }
    .stat-value { font-size: 28px; font-weight: 700; background: linear-gradient(135deg, #f1f5f9 0%%, #94a3b8 100%%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .stat-label { font-size: 11px; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat.critical .stat-value { background: linear-gradient(135deg, #f87171 0%%, #dc2626 100%%); -webkit-background-clip: text; }
    .stat.high .stat-value { background: linear-gradient(135deg, #fb923c 0%%, #ea580c 100%%); -webkit-background-clip: text; }
    .legend-item { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid rgba(51, 65, 85, 0.5); }
    .legend-icon { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; }
    .legend-info { flex: 1; }
    .legend-name { font-size: 13px; color: #e2e8f0; font-weight: 500; }
    .legend-desc { font-size: 11px; color: #64748b; }
    .legend-count { font-size: 12px; color: #94a3b8; background: rgba(99, 102, 241, 0.15); padding: 4px 10px; border-radius: 20px; font-weight: 500; }
    .node { cursor: pointer; }
    .node:hover .node-bg { filter: brightness(1.3); }
    .node-label { font-size: 11px; fill: #94a3b8; font-weight: 500; text-anchor: middle; }
    .link { fill: none; stroke-linecap: round; }
    .flow-particle { fill: #6366f1; }
    #tooltip { position: absolute; background: rgba(15, 23, 42, 0.98); backdrop-filter: blur(8px); border: 1px solid #334155; border-radius: 16px; padding: 20px; font-size: 13px; pointer-events: none; max-width: 340px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); z-index: 1000; display: none; }
    #tooltip .tip-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #334155; }
    #tooltip .tip-icon { width: 40px; height: 40px; }
    #tooltip .tip-title { font-size: 15px; font-weight: 600; color: #f1f5f9; }
    #tooltip .tip-type { font-size: 12px; color: #64748b; }
    #tooltip .tip-risk { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px; }
    #tooltip .tip-risk.critical { background: rgba(248, 113, 113, 0.15); color: #f87171; }
    #tooltip .tip-risk.high { background: rgba(251, 146, 60, 0.15); color: #fb923c; }
    #tooltip .tip-risk.medium { background: rgba(250, 204, 21, 0.15); color: #facc15; }
    #tooltip .tip-findings { margin-top: 12px; }
    #tooltip .tip-finding-item { margin: 10px 0; padding: 10px; background: rgba(248, 113, 113, 0.08); border-radius: 8px; border-left: 3px solid #f87171; }
    #tooltip .tip-finding { color: #f87171; font-size: 12px; font-weight: 500; margin-bottom: 6px; }
    #tooltip .tip-fix { font-size: 11px; color: #94a3b8; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .cis-tag { background: linear-gradient(135deg, #6366f1 0%%, #8b5cf6 100%%); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; white-space: nowrap; }
    .layer-label { font-size: 10px; fill: #475569; text-transform: uppercase; letter-spacing: 2px; font-weight: 600; }
    #controls { position: absolute; bottom: 24px; left: 50%%; transform: translateX(-50%%); display: flex; gap: 8px; background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); padding: 8px; border-radius: 12px; border: 1px solid #334155; }
    #controls button { background: transparent; border: none; color: #94a3b8; padding: 10px 18px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
    #controls button:hover { background: rgba(99, 102, 241, 0.1); color: #e2e8f0; }
    #controls button.active { background: #6366f1; color: #fff; }
    @keyframes flowParticle { 0%% { offset-distance: 0%%; opacity: 0; } 10%% { opacity: 1; } 90%% { opacity: 1; } 100%% { offset-distance: 100%%; opacity: 0; } }

    /* Detail Panel */
    #detail-panel { position: fixed; top: 0; right: -450px; width: 450px; height: 100vh; background: linear-gradient(180deg, #1e293b 0%%, #0f172a 100%%); border-left: 1px solid #334155; box-shadow: -8px 0 32px rgba(0,0,0,0.4); transition: right 0.3s ease; z-index: 2000; overflow-y: auto; }
    #detail-panel.open { right: 0; }
    .panel-header { padding: 20px 24px; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 16px; position: sticky; top: 0; background: linear-gradient(180deg, #1e293b 0%%, #1e293b 100%%); z-index: 10; }
    .panel-close { background: none; border: none; color: #94a3b8; cursor: pointer; padding: 8px; border-radius: 8px; transition: all 0.2s; font-size: 20px; }
    .panel-close:hover { background: rgba(248, 113, 113, 0.1); color: #f87171; }
    .panel-icon { width: 48px; height: 48px; }
    .panel-title-section { flex: 1; }
    .panel-title { font-size: 18px; font-weight: 600; color: #f1f5f9; margin-bottom: 2px; }
    .panel-subtitle { font-size: 13px; color: #64748b; }
    .panel-content { padding: 0 24px 24px; }
    .panel-section { margin-top: 24px; }
    .panel-section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    .panel-section-title::before { content: ''; width: 3px; height: 12px; background: #6366f1; border-radius: 2px; }
    .detail-risk { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 8px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .detail-risk.critical { background: rgba(248, 113, 113, 0.15); color: #f87171; }
    .detail-risk.high { background: rgba(251, 146, 60, 0.15); color: #fb923c; }
    .detail-risk.medium { background: rgba(250, 204, 21, 0.15); color: #facc15; }
    .detail-risk.low { background: rgba(74, 222, 128, 0.15); color: #4ade80; }
    .detail-risk.info { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
    .info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .info-item { background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 10px; padding: 14px; }
    .info-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
    .info-value { font-size: 14px; color: #e2e8f0; font-weight: 500; word-break: break-word; }
    .info-value.bool-true { color: #f87171; }
    .info-value.bool-false { color: #4ade80; }
    .labels-container { display: flex; flex-wrap: wrap; gap: 8px; }
    .label-tag { display: inline-flex; align-items: center; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 6px; padding: 6px 10px; font-size: 12px; }
    .label-key { color: #a5b4fc; margin-right: 6px; }
    .label-value { color: #e2e8f0; }
    .finding-card { background: rgba(248, 113, 113, 0.08); border: 1px solid rgba(248, 113, 113, 0.2); border-left: 4px solid #f87171; border-radius: 10px; padding: 16px; margin-bottom: 12px; }
    .finding-text { font-size: 13px; color: #f87171; font-weight: 500; margin-bottom: 10px; }
    .finding-cis-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
    .finding-cis-title { font-size: 12px; color: #e2e8f0; font-weight: 500; }
    .finding-subsection { margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(248, 113, 113, 0.15); }
    .finding-subsection-title { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-bottom: 6px; }
    .finding-quick-fix { font-size: 12px; color: #4ade80; background: rgba(74, 222, 128, 0.1); padding: 8px 12px; border-radius: 6px; font-family: monospace; margin-bottom: 8px; }
    .finding-remediation { font-size: 12px; color: #cbd5e1; line-height: 1.6; }
    .finding-impact { font-size: 12px; color: #fbbf24; line-height: 1.6; background: rgba(251, 191, 36, 0.08); padding: 10px 12px; border-radius: 6px; margin-top: 8px; }
    .connection-item { display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 10px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; }
    .connection-item:hover { border-color: #6366f1; transform: translateX(4px); }
    .connection-icon { width: 32px; height: 32px; }
    .connection-info { flex: 1; }
    .connection-name { font-size: 13px; color: #e2e8f0; font-weight: 500; }
    .connection-type { font-size: 11px; color: #64748b; }
    .connection-edge { font-size: 11px; color: #6366f1; background: rgba(99, 102, 241, 0.1); padding: 2px 8px; border-radius: 4px; }
    .empty-state { text-align: center; padding: 24px; color: #64748b; font-size: 13px; }
  </style>
</head>
<body>
  <div id="container">
    <div id="sidebar">
      <div class="header">
        <h1>%s</h1>
        <div class="subtitle">Attack Surface Analysis</div>
      </div>
      <div class="section">
        <div class="section-title">Security Posture</div>
        <div class="stats">
          <div class="stat critical"><div class="stat-value">%d</div><div class="stat-label">Critical</div></div>
          <div class="stat high"><div class="stat-value">%d</div><div class="stat-label">High Risk</div></div>
          <div class="stat"><div class="stat-value">%d</div><div class="stat-label">Pods</div></div>
          <div class="stat"><div class="stat-value">%d</div><div class="stat-label">Exposed</div></div>
        </div>
      </div>
      <div class="section">
        <div class="section-title">Attack Flow</div>
        <div id="legend"></div>
      </div>
    </div>
    <div id="graph">
      <div id="tooltip"></div>
      <div id="controls">
        <button onclick="showAll()" class="active">All Resources</button>
        <button onclick="filterRisk('critical')">Critical</button>
        <button onclick="filterRisk('high')">High+</button>
        <button onclick="focusExposed()">Exposed</button>
      </div>
    </div>
  </div>
  <div id="detail-panel">
    <div class="panel-header">
      <button class="panel-close" onclick="closePanel()">×</button>
      <div class="panel-icon" id="panel-icon"></div>
      <div class="panel-title-section">
        <div class="panel-title" id="panel-title"></div>
        <div class="panel-subtitle" id="panel-subtitle"></div>
      </div>
    </div>
    <div class="panel-content" id="panel-content"></div>
  </div>
  <script>
const data = %s;
const container = document.getElementById('graph');
const width = container.clientWidth;
const height = container.clientHeight;
const layerNames = {0:'Internet',1:'Ingress',2:'Services',3:'Workloads',4:'Identity',5:'Secrets',6:'Nodes'};
const usedLayers = [...new Set(data.nodes.map(n => n.layer))].sort((a,b)=>a-b);
const layerWidth = (width - 200) / Math.max(usedLayers.length, 1);
const layerX = {};
usedLayers.forEach((l, i) => layerX[l] = 100 + i * layerWidth);
const icons = {
  external: '<circle cx="24" cy="24" r="20" fill="url(#grad-ext)"/><circle cx="24" cy="24" r="12" fill="none" stroke="#fff" stroke-width="1.5"/><ellipse cx="24" cy="24" rx="20" ry="8" fill="none" stroke="#fff" stroke-width="1.5"/><line x1="24" y1="4" x2="24" y2="44" stroke="#fff" stroke-width="1.5"/>',
  ingress: '<rect x="6" y="12" width="36" height="24" rx="4" fill="url(#grad-ing)"/><path d="M16 24h16M24 18v12" stroke="#fff" stroke-width="2" stroke-linecap="round"/><circle cx="24" cy="24" r="4" fill="#fff"/>',
  service: '<polygon points="24,6 42,16 42,32 24,42 6,32 6,16" fill="url(#grad-svc)"/><circle cx="24" cy="24" r="8" fill="rgba(255,255,255,0.9)"/>',
  pod: '<rect x="8" y="8" width="32" height="32" rx="6" fill="url(#grad-pod)"/><rect x="14" y="14" width="8" height="8" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="26" y="14" width="8" height="8" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="14" y="26" width="8" height="8" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="26" y="26" width="8" height="8" rx="2" fill="rgba(255,255,255,0.9)"/>',
  serviceaccount: '<circle cx="24" cy="18" r="10" fill="url(#grad-sa)"/><path d="M8 42c0-8.837 7.163-16 16-16s16 7.163 16 16" fill="url(#grad-sa)"/>',
  secret: '<rect x="10" y="14" width="28" height="22" rx="4" fill="url(#grad-sec)"/><circle cx="24" cy="25" r="5" fill="rgba(255,255,255,0.9)"/><rect x="22" y="28" width="4" height="6" fill="rgba(255,255,255,0.9)"/>',
  node: '<rect x="6" y="10" width="36" height="28" rx="4" fill="url(#grad-node)"/><rect x="10" y="14" width="14" height="8" rx="2" fill="rgba(255,255,255,0.3)"/><rect x="26" y="14" width="12" height="8" rx="2" fill="rgba(255,255,255,0.3)"/><rect x="10" y="26" width="28" height="8" rx="2" fill="rgba(255,255,255,0.3)"/>',
  role: '<polygon points="24,6 42,16 42,32 24,42 6,32 6,16" fill="url(#grad-role)"/><path d="M24 16v16M16 20l16 8M32 20l-16 8" stroke="rgba(255,255,255,0.5)" stroke-width="1.5"/>',
  clusterrole: '<polygon points="24,6 42,16 42,32 24,42 6,32 6,16" fill="url(#grad-crole)"/><circle cx="24" cy="24" r="6" fill="rgba(255,255,255,0.9)"/>'
};
const typeDesc = {external:'External traffic source',ingress:'HTTP/HTTPS entry point',service:'Network endpoint',pod:'Container workload',serviceaccount:'Kubernetes identity',secret:'Sensitive data',node:'Cluster node',role:'RBAC permissions',clusterrole:'Cluster-wide RBAC'};
const typeCounts = {};
data.nodes.forEach(n => typeCounts[n.type] = (typeCounts[n.type] || 0) + 1);
const legendOrder = ['external','ingress','service','pod','serviceaccount','secret','node'];
document.getElementById('legend').innerHTML = legendOrder.filter(t => typeCounts[t]).map(type => '<div class="legend-item"><div class="legend-icon"><svg width="36" height="36" viewBox="0 0 48 48">' + (icons[type]||icons.pod) + '</svg></div><div class="legend-info"><div class="legend-name">' + type.charAt(0).toUpperCase() + type.slice(1) + '</div><div class="legend-desc">' + (typeDesc[type]||'') + '</div></div><div class="legend-count">' + typeCounts[type] + '</div></div>').join('');
const nodesByLayer = {};
data.nodes.forEach(n => { if(!nodesByLayer[n.layer]) nodesByLayer[n.layer]=[]; nodesByLayer[n.layer].push(n); });
Object.keys(nodesByLayer).forEach(layer => {
  const nodes = nodesByLayer[layer];
  const spacing = Math.min(90, (height - 150) / Math.max(nodes.length, 1));
  const startY = (height - (nodes.length - 1) * spacing) / 2;
  nodes.forEach((n, i) => { n.x = layerX[n.layer] || 100; n.y = startY + i * spacing; });
});
const nodeMap = {}; data.nodes.forEach(n => nodeMap[n.id] = n);
const svg = d3.select('#graph').append('svg');
const defs = svg.append('defs');
[['ext','#f87171','#dc2626'],['ing','#818cf8','#6366f1'],['svc','#60a5fa','#3b82f6'],['pod','#34d399','#10b981'],['sa','#a78bfa','#8b5cf6'],['sec','#fbbf24','#f59e0b'],['node','#94a3b8','#64748b'],['role','#f472b6','#ec4899'],['crole','#e879f9','#d946ef']].forEach(([id,c1,c2]) => {
  const g = defs.append('linearGradient').attr('id','grad-'+id).attr('x1','0%%').attr('y1','0%%').attr('x2','100%%').attr('y2','100%%');
  g.append('stop').attr('offset','0%%').attr('stop-color',c1);
  g.append('stop').attr('offset','100%%').attr('stop-color',c2);
});
const glow = defs.append('filter').attr('id','glow');
glow.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
glow.append('feMerge').html('<feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/>');
const g = svg.append('g');
const zoom = d3.zoom().scaleExtent([0.3,3]).on('zoom',e=>g.attr('transform',e.transform));
svg.call(zoom);
Object.entries(layerX).forEach(([layer, x]) => {
  if(nodesByLayer[layer] && layerNames[layer]) {
    g.append('text').attr('class','layer-label').attr('x',x).attr('y',40).attr('text-anchor','middle').text(layerNames[layer]);
  }
});
const linkG = g.append('g');
const validLinks = data.links.filter(l => nodeMap[l.source] && nodeMap[l.target]);
const links = linkG.selectAll('path').data(validLinks).join('path')
  .attr('class','link')
  .attr('stroke', d => d.risk==='critical'?'#f87171':d.risk==='high'?'#fb923c':'#6366f1')
  .attr('stroke-width', d => d.risk==='critical'?3:d.risk==='high'?2.5:2)
  .attr('stroke-opacity', d => d.risk==='critical'?0.8:d.risk==='high'?0.6:0.4)
  .attr('d', d => {
    const s=nodeMap[d.source], t=nodeMap[d.target];
    const mx=(s.x+t.x)/2, c1=s.x+(t.x-s.x)*0.4, c2=s.x+(t.x-s.x)*0.6;
    return 'M'+s.x+','+s.y+' C'+c1+','+s.y+' '+c2+','+t.y+' '+t.x+','+t.y;
  });
validLinks.filter(l=>l.risk==='critical'||l.risk==='high').forEach((l,i) => {
  const s=nodeMap[l.source], t=nodeMap[l.target];
  const path = linkG.append('path').attr('fill','none').attr('stroke','none')
    .attr('d', 'M'+s.x+','+s.y+' C'+(s.x+(t.x-s.x)*0.4)+','+s.y+' '+(s.x+(t.x-s.x)*0.6)+','+t.y+' '+t.x+','+t.y);
  for(let p=0;p<3;p++) {
    linkG.append('circle').attr('r',4).attr('fill',l.risk==='critical'?'#f87171':'#fb923c').attr('opacity',0.8)
      .style('offset-path','path("'+path.attr('d')+'")')
      .style('animation','flowParticle 2s linear infinite').style('animation-delay',(i*0.3+p*0.6)+'s');
  }
});
const nodeG = g.append('g');
const nodes = nodeG.selectAll('g').data(data.nodes).join('g')
  .attr('class','node')
  .attr('filter', d => (d.risk==='critical'||d.risk==='high')?'url(#glow)':'none')
  .attr('transform', d => 'translate('+(d.x-24)+','+(d.y-24)+')');
nodes.append('g').attr('class','node-bg').html(d => '<svg width="48" height="48" viewBox="0 0 48 48">'+(icons[d.type]||icons.pod)+'</svg>');
nodes.append('text').attr('class','node-label').attr('x',24).attr('y',60).text(d => d.name.length>18?d.name.slice(0,18)+'...':d.name);
if(data.nodes.some(n=>n.risk==='critical'||n.risk==='high')) {
  nodes.filter(d=>d.risk==='critical'||d.risk==='high').append('circle')
    .attr('cx',42).attr('cy',6).attr('r',8).attr('fill',d=>d.risk==='critical'?'#dc2626':'#ea580c');
  nodes.filter(d=>d.risk==='critical'||d.risk==='high').append('text')
    .attr('x',42).attr('y',10).attr('text-anchor','middle').attr('fill','#fff').attr('font-size','10').attr('font-weight','bold').text('!');
}
// Remediation data loaded from compliance controls - pattern -> control info
const remediationData = %s;
function getFix(finding) {
  const findingLower = finding.toLowerCase();
  for(const [pattern, ctrl] of Object.entries(remediationData)) {
    if(findingLower.includes(pattern.toLowerCase())) {
      return {
        cis: ctrl.id,
        title: ctrl.name,
        fix: ctrl.remediation,
        remediation: ctrl.remediation,
        section: ctrl.section,
        severity: ctrl.severity,
        framework: ctrl.framework
      };
    }
  }
  return null;
}
const tooltip = d3.select('#tooltip');
nodes.on('mouseover',(e,d) => {
  let html = '<div class="tip-header"><div class="tip-icon"><svg viewBox="0 0 48 48">'+(icons[d.type]||icons.pod)+'</svg></div><div><div class="tip-title">'+d.name+'</div><div class="tip-type">'+d.type+(d.namespace?' in '+d.namespace:'')+'</div></div></div>';
  html += '<div class="tip-risk '+d.risk+'"><span style="width:8px;height:8px;border-radius:50%%;background:currentColor;display:inline-block"></span>'+d.risk.toUpperCase()+' RISK</div>';
  if(d.findings&&d.findings.length) {
    html+='<div class="tip-findings">';
    d.findings.forEach(f => {
      const fix = getFix(f);
      html += '<div class="tip-finding-item"><div class="tip-finding">'+f+'</div>';
      if(fix) html += '<div class="tip-fix"><span class="cis-tag">CIS '+fix.cis+'</span> '+fix.fix+'</div>';
      html += '</div>';
    });
    html += '</div>';
  }
  tooltip.html(html).style('display','block').style('left',(e.pageX+20)+'px').style('top',(e.pageY-10)+'px');
}).on('mouseout',()=>tooltip.style('display','none'));
nodes.on('click',(e,d) => {
  e.stopPropagation();
  showNodeDetail(d);
});
svg.on('click', (e) => {
  if (e.target === svg.node()) closePanel();
});
svg.on('dblclick',showAll);

// Detail Panel Functions
const panel = document.getElementById('detail-panel');
const panelIcon = document.getElementById('panel-icon');
const panelTitle = document.getElementById('panel-title');
const panelSubtitle = document.getElementById('panel-subtitle');
const panelContent = document.getElementById('panel-content');

function closePanel() {
  panel.classList.remove('open');
}

function showNodeDetail(node) {
  // Highlight connected nodes
  nodes.style('opacity',0.15); links.style('opacity',0.05);
  const conn = new Set([node.id]);
  data.links.forEach(l=>{if(l.source===node.id)conn.add(l.target);if(l.target===node.id)conn.add(l.source);});
  nodes.filter(n=>conn.has(n.id)).style('opacity',1);
  links.filter(l=>l.source===node.id||l.target===node.id).style('opacity',0.9);

  // Update panel header
  panelIcon.innerHTML = '<svg viewBox="0 0 48 48">'+(icons[node.type]||icons.pod)+'</svg>';
  panelTitle.textContent = node.name;
  panelSubtitle.textContent = node.type.charAt(0).toUpperCase() + node.type.slice(1) + (node.namespace ? ' in ' + node.namespace : '');

  // Build panel content
  let html = '';

  // Risk badge
  html += '<div class="panel-section"><div class="detail-risk ' + node.risk + '"><span style="width:8px;height:8px;border-radius:50%%;background:currentColor;display:inline-block"></span>' + node.risk.toUpperCase() + ' RISK (Score: ' + node.riskScore + ')</div></div>';

  // Properties section
  if (node.properties && Object.keys(node.properties).length > 0) {
    html += '<div class="panel-section"><div class="panel-section-title">Properties</div><div class="info-grid">';
    for (const [key, val] of Object.entries(node.properties)) {
      let valStr = String(val);
      let valClass = '';
      if (typeof val === 'boolean') {
        valClass = val ? 'bool-true' : 'bool-false';
        valStr = val ? 'Yes' : 'No';
      }
      html += '<div class="info-item"><div class="info-label">' + key + '</div><div class="info-value ' + valClass + '">' + valStr + '</div></div>';
    }
    html += '</div></div>';
  }

  // Labels section
  if (node.labels && Object.keys(node.labels).length > 0) {
    html += '<div class="panel-section"><div class="panel-section-title">Labels</div><div class="labels-container">';
    for (const [key, val] of Object.entries(node.labels)) {
      html += '<div class="label-tag"><span class="label-key">' + key + ':</span><span class="label-value">' + val + '</span></div>';
    }
    html += '</div></div>';
  }

  // Findings section with CIS controls and full remediation
  if (node.findings && node.findings.length > 0) {
    html += '<div class="panel-section"><div class="panel-section-title">Security Findings (' + node.findings.length + ')</div>';
    node.findings.forEach(f => {
      const fix = getFix(f);
      html += '<div class="finding-card"><div class="finding-text">' + f + '</div>';
      if (fix) {
        html += '<div class="finding-cis-header"><span class="cis-tag">CIS ' + fix.cis + '</span><span class="finding-cis-title">' + fix.title + '</span></div>';
        html += '<div class="finding-subsection"><div class="finding-subsection-title">Quick Fix</div><div class="finding-quick-fix">' + fix.fix + '</div></div>';
        html += '<div class="finding-subsection"><div class="finding-subsection-title">Remediation</div><div class="finding-remediation">' + fix.remediation + '</div></div>';
        if (fix.impact) {
          html += '<div class="finding-subsection"><div class="finding-subsection-title">Impact</div><div class="finding-impact">' + fix.impact + '</div></div>';
        }
      }
      html += '</div>';
    });
    html += '</div>';
  }

  // Connections section
  const incoming = data.links.filter(l => l.target === node.id);
  const outgoing = data.links.filter(l => l.source === node.id);

  if (incoming.length > 0) {
    html += '<div class="panel-section"><div class="panel-section-title">Incoming Connections (' + incoming.length + ')</div>';
    incoming.forEach(link => {
      const srcNode = nodeMap[link.source];
      if (srcNode) {
        html += '<div class="connection-item" onclick="navigateToNode(\''+srcNode.id+'\')">';
        html += '<div class="connection-icon"><svg viewBox="0 0 48 48">'+(icons[srcNode.type]||icons.pod)+'</svg></div>';
        html += '<div class="connection-info"><div class="connection-name">' + srcNode.name + '</div><div class="connection-type">' + srcNode.type + '</div></div>';
        html += '<span class="connection-edge">' + link.type + '</span></div>';
      }
    });
    html += '</div>';
  }

  if (outgoing.length > 0) {
    html += '<div class="panel-section"><div class="panel-section-title">Outgoing Connections (' + outgoing.length + ')</div>';
    outgoing.forEach(link => {
      const tgtNode = nodeMap[link.target];
      if (tgtNode) {
        html += '<div class="connection-item" onclick="navigateToNode(\''+tgtNode.id+'\')">';
        html += '<div class="connection-icon"><svg viewBox="0 0 48 48">'+(icons[tgtNode.type]||icons.pod)+'</svg></div>';
        html += '<div class="connection-info"><div class="connection-name">' + tgtNode.name + '</div><div class="connection-type">' + tgtNode.type + '</div></div>';
        html += '<span class="connection-edge">' + link.type + '</span></div>';
      }
    });
    html += '</div>';
  }

  if (!node.properties && !node.labels && (!node.findings || node.findings.length === 0) && incoming.length === 0 && outgoing.length === 0) {
    html += '<div class="empty-state">No additional details available</div>';
  }

  panelContent.innerHTML = html;
  panel.classList.add('open');
}

function navigateToNode(nodeId) {
  const node = data.nodes.find(n => n.id === nodeId);
  if (node) showNodeDetail(node);
}
function showAll(){nodes.style('opacity',1);links.style('opacity',l=>l.risk==='critical'?0.8:l.risk==='high'?0.6:0.4);setActive(0);closePanel();}
function filterRisk(r){nodes.style('opacity',d=>(r==='critical'?d.risk==='critical':d.risk==='critical'||d.risk==='high')?1:0.1);links.style('opacity',l=>(r==='critical'?l.risk==='critical':l.risk==='critical'||l.risk==='high')?0.9:0.05);setActive(r==='critical'?1:2);}
function focusExposed(){nodes.style('opacity',d=>d.layer<=2?1:0.15);links.style('opacity',l=>{const s=nodeMap[l.source],t=nodeMap[l.target];return(s&&t&&(s.layer<=2||t.layer<=2))?0.8:0.05;});setActive(3);}
function setActive(i){document.querySelectorAll('#controls button').forEach((b,j)=>b.classList.toggle('active',i===j));}
svg.transition().duration(800).call(zoom.transform,d3.zoomIdentity.translate(50,0).scale(0.9));
  </script>
</body>
</html>`, e.g.ClusterName, e.g.ClusterName, criticalCount, highCount,
		podCount, serviceCount, string(jsonData), string(remediationData))

	return html
}
