package service

import (
	"context"
	"testing"

	"hermes/internal/providerapi"

	"github.com/stretchr/testify/assert"
)

func TestLookupService_MockAdapter(t *testing.T) {
	mock := &providerapi.MockAdapter{
		CodeFunc: func() string { return "mock" },
		SupportedTypesFunc: func() []string { return []string{"ip"} },
		LookupFunc: func(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
			return providerapi.Result{
				ProviderCode: "mock",
				Success:      true,
				Data:         map[string]interface{}{"score": 0},
			}, nil
		},
	}
	assert.Equal(t, "mock", mock.Code())
	assert.Equal(t, []string{"ip"}, mock.SupportedTypes())
	res, err := mock.Lookup(context.Background(), "ip", "8.8.8.8")
	assert.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, "mock", res.ProviderCode)
}
