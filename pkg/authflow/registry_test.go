package authflow

import (
	"net/http"
	"testing"
)

type mockFlow struct {
	name   string
	routes []Route
}

func (f *mockFlow) Name() string    { return f.name }
func (f *mockFlow) Routes() []Route { return f.routes }

func TestRegistry_RegisterAndBuild(t *testing.T) {
	r := NewRegistry()
	err := r.Register("test-flow", func(deps Deps) (Flow, error) {
		return &mockFlow{
			name: "test-flow",
			routes: []Route{
				{Pattern: "/test", Handler: http.NotFoundHandler(), RateLimited: true},
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	flows, err := r.Build(Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].Name() != "test-flow" {
		t.Errorf("Name = %q, want %q", flows[0].Name(), "test-flow")
	}
	routes := flows[0].Routes()
	if len(routes) != 1 || routes[0].Pattern != "/test" {
		t.Errorf("unexpected routes: %v", routes)
	}
}

func TestRegistry_DuplicateRegister(t *testing.T) {
	r := NewRegistry()
	factory := func(deps Deps) (Flow, error) { return &mockFlow{name: "a"}, nil }

	if err := r.Register("a", factory); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register("a", factory); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("a", func(deps Deps) (Flow, error) { return &mockFlow{name: "a"}, nil })
	_ = r.Register("b", func(deps Deps) (Flow, error) { return &mockFlow{name: "b"}, nil })

	names := r.List()
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

func TestRegistry_BuildEmpty(t *testing.T) {
	r := NewRegistry()
	flows, err := r.Build(Deps{})
	if err != nil {
		t.Fatalf("Build empty: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(flows))
	}
}
