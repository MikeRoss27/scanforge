package modules

import (
	"fmt"
)

type Registry struct {
	modules map[string]Module
}

func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

func (r *Registry) Resolve(names []string) ([]Module, error) {
	var resolved []Module
	for _, name := range names {
		m, ok := r.Get(name)
		if !ok {
			return nil, fmt.Errorf("module %q not found in registry", name)
		}
		resolved = append(resolved, m)
	}
	return resolved, nil
}
