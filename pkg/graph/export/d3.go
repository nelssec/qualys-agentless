package export

import (
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/graph"
)

type D3Exporter struct {
	g *graph.SecurityGraph
}

type D3Graph struct {
	Nodes []D3Node `json:"nodes"`
	Links []D3Link `json:"links"`
	Meta  D3Meta   `json:"meta"`
}

type D3Node struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Namespace  string                 `json:"namespace,omitempty"`
	Risk       string                 `json:"risk"`
	RiskScore  int                    `json:"riskScore"`
	Group      int                    `json:"group"`
	Findings   []string               `json:"findings,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type D3Link struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       string                 `json:"type"`
	Risk       string                 `json:"risk,omitempty"`
	Label      string                 `json:"label,omitempty"`
	Value      int                    `json:"value"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type D3Meta struct {
	ClusterName   string         `json:"clusterName"`
	GeneratedAt   string         `json:"generatedAt"`
	TotalNodes    int            `json:"totalNodes"`
	TotalLinks    int            `json:"totalLinks"`
	Summary       graph.GraphSummary `json:"summary"`
}

func NewD3Exporter(g *graph.SecurityGraph) *D3Exporter {
	return &D3Exporter{g: g}
}

func (e *D3Exporter) Export() ([]byte, error) {
	d3Graph := e.buildD3Graph()
	return json.MarshalIndent(d3Graph, "", "  ")
}

func (e *D3Exporter) ExportString() (string, error) {
	data, err := e.Export()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (e *D3Exporter) buildD3Graph() D3Graph {
	nodes := make([]D3Node, 0, len(e.g.Nodes))
	links := make([]D3Link, 0, len(e.g.Edges))

	for _, node := range e.g.Nodes {
		d3Node := D3Node{
			ID:         node.ID,
			Name:       node.Name,
			Type:       string(node.Type),
			Namespace:  node.Namespace,
			Risk:       string(node.Risk),
			RiskScore:  node.RiskScore,
			Group:      e.getNodeGroup(node.Type),
			Findings:   node.Findings,
			Properties: node.Properties,
		}
		nodes = append(nodes, d3Node)
	}

	for _, edge := range e.g.Edges {
		d3Link := D3Link{
			Source:     edge.Source,
			Target:     edge.Target,
			Type:       string(edge.Type),
			Risk:       string(edge.Risk),
			Label:      edge.Label,
			Value:      e.getLinkValue(edge),
			Properties: edge.Properties,
		}
		links = append(links, d3Link)
	}

	return D3Graph{
		Nodes: nodes,
		Links: links,
		Meta: D3Meta{
			ClusterName: e.g.ClusterName,
			GeneratedAt: e.g.GeneratedAt,
			TotalNodes:  len(nodes),
			TotalLinks:  len(links),
			Summary:     e.g.Summary,
		},
	}
}

func (e *D3Exporter) getNodeGroup(nodeType graph.NodeType) int {
	switch nodeType {
	case graph.NodePod:
		return 1
	case graph.NodeServiceAccount:
		return 2
	case graph.NodeRole, graph.NodeClusterRole:
		return 3
	case graph.NodeRoleBinding, graph.NodeClusterRoleBinding:
		return 4
	case graph.NodeSecret:
		return 5
	case graph.NodeService:
		return 6
	case graph.NodeIngress:
		return 7
	case graph.NodeNode:
		return 8
	case graph.NodeNamespace:
		return 9
	case graph.NodeExternal:
		return 10
	default:
		return 0
	}
}

func (e *D3Exporter) getLinkValue(edge graph.Edge) int {
	switch edge.Risk {
	case graph.RiskCritical:
		return 5
	case graph.RiskHigh:
		return 4
	case graph.RiskMedium:
		return 3
	case graph.RiskLow:
		return 2
	default:
		return 1
	}
}

func (e *D3Exporter) filterConnectedNodes() D3Graph {
	connectedIDs := make(map[string]bool)
	for _, edge := range e.g.Edges {
		connectedIDs[edge.Source] = true
		connectedIDs[edge.Target] = true
	}

	nodes := make([]D3Node, 0)
	for _, node := range e.g.Nodes {
		if connectedIDs[node.ID] {
			nodes = append(nodes, D3Node{
				ID:         node.ID,
				Name:       node.Name,
				Type:       string(node.Type),
				Namespace:  node.Namespace,
				Risk:       string(node.Risk),
				RiskScore:  node.RiskScore,
				Group:      e.getNodeGroup(node.Type),
				Findings:   node.Findings,
				Properties: node.Properties,
			})
		}
	}

	links := make([]D3Link, 0)
	for _, edge := range e.g.Edges {
		links = append(links, D3Link{
			Source:     edge.Source,
			Target:     edge.Target,
			Type:       string(edge.Type),
			Risk:       string(edge.Risk),
			Label:      edge.Label,
			Value:      e.getLinkValue(edge),
			Properties: edge.Properties,
		})
	}

	return D3Graph{
		Nodes: nodes,
		Links: links,
		Meta: D3Meta{
			ClusterName: e.g.ClusterName,
			GeneratedAt: e.g.GeneratedAt,
			TotalNodes:  len(nodes),
			TotalLinks:  len(links),
			Summary:     e.g.Summary,
		},
	}
}

func (e *D3Exporter) ExportHTML() string {
	filtered := e.filterConnectedNodes()
	jsonData, _ := json.MarshalIndent(filtered, "", "  ")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s - Security Graph</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
    #graph { width: 100vw; height: 100vh; }
    .node { cursor: pointer; }
    .node text { font-size: 11px; fill: #c9d1d9; pointer-events: none; font-weight: 500; }
    .link { stroke-opacity: 0.7; }
    #tooltip { position: absolute; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 12px; border-radius: 6px; font-size: 12px; pointer-events: none; max-width: 350px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
    #legend { position: fixed; top: 10px; right: 10px; background: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 6px; font-size: 12px; max-height: 90vh; overflow-y: auto; }
    #legend h3 { margin: 0 0 10px 0; color: #58a6ff; font-size: 14px; }
    .legend-item { display: flex; align-items: center; margin: 4px 0; }
    .legend-color { width: 16px; height: 16px; margin-right: 8px; border-radius: 50%%; border: 2px solid #30363d; }
    #summary { position: fixed; top: 10px; left: 10px; background: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 6px; font-size: 13px; }
    #summary h3 { margin: 0 0 8px 0; color: #58a6ff; }
    #summary .stat { margin: 4px 0; }
    #summary .critical { color: #f85149; font-weight: bold; }
    #summary .high { color: #d29922; }
    #controls { position: fixed; bottom: 10px; left: 10px; background: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; display: flex; flex-wrap: wrap; gap: 5px; }
    button { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
    button:hover { background: #30363d; border-color: #8b949e; }
    button.active { background: #238636; border-color: #238636; }
    #typeFilters { position: fixed; bottom: 10px; right: 10px; background: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; }
    #typeFilters label { display: block; margin: 3px 0; cursor: pointer; font-size: 12px; }
    #typeFilters input { margin-right: 6px; }
  </style>
</head>
<body>
  <div id="graph"></div>
  <div id="tooltip" style="display: none;"></div>
  <div id="legend">
    <h3>Risk Levels</h3>
    <div class="legend-item"><div class="legend-color" style="background:#f85149"></div>Critical</div>
    <div class="legend-item"><div class="legend-color" style="background:#d29922"></div>High</div>
    <div class="legend-item"><div class="legend-color" style="background:#e3b341"></div>Medium</div>
    <div class="legend-item"><div class="legend-color" style="background:#3fb950"></div>Low</div>
    <div class="legend-item"><div class="legend-color" style="background:#8b949e"></div>Info</div>
    <h3 style="margin-top:15px">Node Types</h3>
    <div class="legend-item"><div class="legend-color" style="background:#58a6ff"></div>Pod</div>
    <div class="legend-item"><div class="legend-color" style="background:#3fb950"></div>ServiceAccount</div>
    <div class="legend-item"><div class="legend-color" style="background:#d29922"></div>Role</div>
    <div class="legend-item"><div class="legend-color" style="background:#a371f7"></div>RoleBinding</div>
    <div class="legend-item"><div class="legend-color" style="background:#f778ba"></div>Secret</div>
    <div class="legend-item"><div class="legend-color" style="background:#79c0ff"></div>Service</div>
    <div class="legend-item"><div class="legend-color" style="background:#ffa657"></div>Ingress</div>
    <div class="legend-item"><div class="legend-color" style="background:#8b949e"></div>Node</div>
    <div class="legend-item"><div class="legend-color" style="background:#f85149"></div>External</div>
  </div>
  <div id="summary">
    <h3>%s</h3>
    <div class="stat">Connected Nodes: %d</div>
    <div class="stat">Relationships: %d</div>
    <div class="stat critical">High Risk Nodes: %d</div>
    <div class="stat">External Exposures: %d</div>
  </div>
  <div id="controls">
    <button onclick="zoomIn()">Zoom +</button>
    <button onclick="zoomOut()">Zoom -</button>
    <button onclick="resetZoom()">Reset View</button>
    <button onclick="filterRisk('critical')" id="btn-critical">Critical Only</button>
    <button onclick="filterRisk('high')" id="btn-high">High+</button>
    <button onclick="filterByType('pod')" id="btn-pods">Pods</button>
    <button onclick="filterByType('serviceaccount')" id="btn-sa">ServiceAccounts</button>
    <button onclick="showAll()" id="btn-all" class="active">Show All</button>
  </div>
  <script>
    const graphData = %s;
    const width = window.innerWidth;
    const height = window.innerHeight;
    const riskColors = { critical: '#f85149', high: '#d29922', medium: '#e3b341', low: '#3fb950', info: '#8b949e' };
    const typeColors = { pod: '#58a6ff', serviceaccount: '#3fb950', role: '#d29922', clusterrole: '#d29922', rolebinding: '#a371f7', clusterrolebinding: '#a371f7', secret: '#f778ba', service: '#79c0ff', ingress: '#ffa657', node: '#8b949e', namespace: '#8b949e', external: '#f85149', networkpolicy: '#56d364' };

    const svg = d3.select('#graph').append('svg').attr('width', width).attr('height', height);
    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.1, 10]).on('zoom', (event) => g.attr('transform', event.transform));
    svg.call(zoom);

    const simulation = d3.forceSimulation(graphData.nodes)
      .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(80).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(25))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.05));

    const link = g.append('g').selectAll('line').data(graphData.links).join('line')
      .attr('class', 'link')
      .attr('stroke', d => riskColors[d.risk] || '#30363d')
      .attr('stroke-width', d => Math.max(1, d.value));

    const node = g.append('g').selectAll('g').data(graphData.nodes).join('g')
      .attr('class', 'node')
      .call(d3.drag().on('start', dragstarted).on('drag', dragged).on('end', dragended));

    node.append('circle')
      .attr('r', d => 6 + Math.min(d.riskScore / 15, 8))
      .attr('fill', d => typeColors[d.type] || '#8b949e')
      .attr('stroke', d => riskColors[d.risk] || '#30363d')
      .attr('stroke-width', d => d.risk === 'critical' ? 3 : d.risk === 'high' ? 2 : 1);

    node.append('text').attr('dx', 14).attr('dy', 4)
      .text(d => d.name.length > 25 ? d.name.substring(0, 25) + '...' : d.name);

    const tooltip = d3.select('#tooltip');
    node.on('mouseover', (event, d) => {
      let html = '<strong style="color:#58a6ff">' + d.name + '</strong><br><span style="color:#8b949e">Type:</span> ' + d.type + '<br><span style="color:#8b949e">Namespace:</span> ' + (d.namespace || 'cluster-wide') + '<br><span style="color:#8b949e">Risk:</span> <span style="color:' + (riskColors[d.risk] || '#8b949e') + '">' + d.risk.toUpperCase() + '</span>';
      if (d.findings && d.findings.length) { html += '<br><br><span style="color:#f85149">Findings:</span><br>' + d.findings.map(f => '- ' + f).join('<br>'); }
      tooltip.style('display', 'block').html(html).style('left', (event.pageX + 15) + 'px').style('top', (event.pageY + 15) + 'px');
    }).on('mouseout', () => tooltip.style('display', 'none'));

    node.on('click', (event, d) => {
      node.style('opacity', n => n.id === d.id ? 1 : 0.2);
      link.style('opacity', l => (l.source.id === d.id || l.target.id === d.id) ? 1 : 0.1);
      const connected = new Set();
      graphData.links.forEach(l => { if (l.source.id === d.id) connected.add(l.target.id); if (l.target.id === d.id) connected.add(l.source.id); });
      node.style('opacity', n => n.id === d.id || connected.has(n.id) ? 1 : 0.15);
    });

    svg.on('click', (event) => { if (event.target.tagName === 'svg') showAll(); });

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
    });

    function dragstarted(event) { if (!event.active) simulation.alphaTarget(0.3).restart(); event.subject.fx = event.subject.x; event.subject.fy = event.subject.y; }
    function dragged(event) { event.subject.fx = event.x; event.subject.fy = event.y; }
    function dragended(event) { if (!event.active) simulation.alphaTarget(0); event.subject.fx = null; event.subject.fy = null; }
    function zoomIn() { svg.transition().call(zoom.scaleBy, 1.5); }
    function zoomOut() { svg.transition().call(zoom.scaleBy, 0.67); }
    function resetZoom() { svg.transition().call(zoom.transform, d3.zoomIdentity); }
    function clearActive() { document.querySelectorAll('#controls button').forEach(b => b.classList.remove('active')); }
    function filterRisk(level) {
      clearActive(); document.getElementById('btn-' + level).classList.add('active');
      const levels = level === 'critical' ? ['critical'] : ['critical', 'high'];
      node.style('opacity', d => levels.includes(d.risk) ? 1 : 0.1);
      link.style('opacity', 0.1);
    }
    function filterByType(type) {
      clearActive(); document.getElementById('btn-' + (type === 'pod' ? 'pods' : 'sa')).classList.add('active');
      node.style('opacity', d => d.type === type ? 1 : 0.15);
      link.style('opacity', l => (l.source.type === type || l.target.type === type) ? 0.6 : 0.05);
    }
    function showAll() { clearActive(); document.getElementById('btn-all').classList.add('active'); node.style('opacity', 1); link.style('opacity', 0.7); }
  </script>
</body>
</html>`, e.g.ClusterName, e.g.ClusterName, filtered.Meta.TotalNodes, filtered.Meta.TotalLinks,
		e.g.Summary.HighRiskNodes, e.g.Summary.ExternalExposures, string(jsonData))

	return html
}
