package providerapi

import "context"

// MockAdapter is a test double for Adapter.
type MockAdapter struct {
	CodeFunc          func() string
	LookupFunc        func(ctx context.Context, indicatorType string, value string) (Result, error)
	SupportedTypesFunc func() []string
}

func (m *MockAdapter) Code() string {
	if m.CodeFunc != nil {
		return m.CodeFunc()
	}
	return "mock"
}

func (m *MockAdapter) Lookup(ctx context.Context, indicatorType string, value string) (Result, error) {
	if m.LookupFunc != nil {
		return m.LookupFunc(ctx, indicatorType, value)
	}
	return Result{ProviderCode: "mock", Success: true, Data: map[string]interface{}{}}, nil
}

func (m *MockAdapter) SupportedTypes() []string {
	if m.SupportedTypesFunc != nil {
		return m.SupportedTypesFunc()
	}
	return []string{"ip", "domain", "url"}
}
