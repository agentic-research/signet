package authflow

import (
	"fmt"
	"sync"
)

// FlowFactory creates a Flow from shared dependencies.
type FlowFactory func(deps Deps) (Flow, error)

// Registry maintains a mapping of flow names to their factories.
// Follows the venturi provider pattern: Registry + Factory + explicit Register().
type Registry struct {
	mu        sync.RWMutex
	factories map[string]FlowFactory
}

// NewRegistry creates a new flow registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]FlowFactory),
	}
}

// Register adds a flow factory to the registry.
func (r *Registry) Register(name string, factory FlowFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// Build instantiates all registered flows with the given dependencies.
func (r *Registry) Build(deps Deps) ([]Flow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	flows := make([]Flow, 0, len(r.factories))
	for name, factory := range r.factories {
		flow, err := factory(deps)
		if err != nil {
			return nil, fmt.Errorf("flow %q: %w", name, err)
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

// List returns all registered flow names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// DefaultRegistry is the global flow registry.
// Flows register via init() in their package, following the database/sql driver pattern.
var DefaultRegistry = NewRegistry()
