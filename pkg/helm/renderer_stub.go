//go:build nohelm

package helm

import (
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
)

type Renderer struct{}

type RenderOptions struct {
	ReleaseName string
	Namespace   string
	ValueFiles  []string
	Values      []string
	APIVersions []string
}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func (r *Renderer) RenderChart(chartPath string, opts RenderOptions) (*inventory.ClusterInventory, error) {
	return nil, fmt.Errorf("Helm support not compiled in (build without -tags nohelm)")
}

func (r *Renderer) RenderDirectory(dir string, opts RenderOptions) (*inventory.ClusterInventory, error) {
	return nil, fmt.Errorf("Helm support not compiled in (build without -tags nohelm)")
}
