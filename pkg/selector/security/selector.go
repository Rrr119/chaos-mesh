// Package security selects Secret backed security chaos targets.
package security

import (
	"context"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

type SelectImpl struct{}

func New() *SelectImpl {
	return &SelectImpl{}
}

// Select returns the configured secret selector as the single target.
func (impl *SelectImpl) Select(_ context.Context, selector *v1alpha1.SecuritySelector) ([]*v1alpha1.SecuritySelector, error) {
	return []*v1alpha1.SecuritySelector{selector}, nil
}
