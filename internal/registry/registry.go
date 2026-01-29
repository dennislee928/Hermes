package registry

import (
	"hermes/internal/config"
	"hermes/internal/provider"
	"hermes/internal/provider/abuseipdb"
	"hermes/internal/provider/circl"
	"hermes/internal/provider/hibp"
	"hermes/internal/provider/nvd"
	"hermes/internal/provider/phishtank"
	"hermes/internal/provider/urlscan"
	"hermes/internal/provider/virustotal"
)

// Registry holds all provider adapters and selects by indicator type.
type Registry struct {
	adapters []provider.Adapter
	byCode   map[string]provider.Adapter
}

// NewRegistry builds a registry from config.
func NewRegistry(cfg *config.Config) *Registry {
	byCode := make(map[string]provider.Adapter)
	adapters := []provider.Adapter{
		abuseipdb.NewClient(cfg.AbuseIPDBAPIKey),
		virustotal.NewClient(cfg.VirusTotalAPIKey),
		phishtank.NewClient(cfg.PhishTankAppKey),
		urlscan.NewClient(cfg.URLScanAPIKey),
		hibp.NewClient(cfg.HIBPAPIKey),
		nvd.NewClient(cfg.NVDAPIKey),
		circl.NewClient(),
	}
	for _, a := range adapters {
		byCode[a.Code()] = a
	}
	return &Registry{adapters: adapters, byCode: byCode}
}

// AdaptersForType returns adapters that support the given indicator type.
func (r *Registry) AdaptersForType(t provider.IndicatorType) []provider.Adapter {
	var out []provider.Adapter
	for _, a := range r.adapters {
		for _, st := range a.SupportedTypes() {
			if st == t {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// AdapterByCode returns the adapter for the given provider code, or nil.
func (r *Registry) AdapterByCode(code string) provider.Adapter {
	return r.byCode[code]
}

// AllCodes returns all registered provider codes.
func (r *Registry) AllCodes() []string {
	codes := make([]string, 0, len(r.byCode))
	for c := range r.byCode {
		codes = append(codes, c)
	}
	return codes
}
