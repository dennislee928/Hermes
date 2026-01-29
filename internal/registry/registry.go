package registry

import (
	"hermes/internal/config"
	"hermes/internal/providerapi"
	"hermes/internal/provider/abuseipdb"
	"hermes/internal/provider/binaryedge"
	"hermes/internal/provider/circl"
	"hermes/internal/provider/criminalip"
	"hermes/internal/provider/emailrep"
	"hermes/internal/provider/hibp"
	"hermes/internal/provider/hybridanalysis"
	"hermes/internal/provider/ipasnhistory"
	"hermes/internal/provider/malshare"
	"hermes/internal/provider/malwarebazaar"
	"hermes/internal/provider/nvd"
	"hermes/internal/provider/phishtank"
	"hermes/internal/provider/pulsedive"
	"hermes/internal/provider/ssllabs"
	"hermes/internal/provider/threatminer"
	"hermes/internal/provider/urlscan"
	"hermes/internal/provider/virustotal"
	"hermes/internal/provider/vulners"
)

// Registry holds all provider adapters and selects by indicator type.
type Registry struct {
	adapters []providerapi.Adapter
	byCode   map[string]providerapi.Adapter
}

// NewRegistry builds a registry from config.
func NewRegistry(cfg *config.Config) *Registry {
	byCode := make(map[string]providerapi.Adapter)
	adapters := []providerapi.Adapter{
		abuseipdb.NewClient(cfg.AbuseIPDBAPIKey),
		virustotal.NewClient(cfg.VirusTotalAPIKey),
		phishtank.NewClient(cfg.PhishTankAppKey),
		urlscan.NewClient(cfg.URLScanAPIKey),
		hibp.NewClient(cfg.HIBPAPIKey),
		nvd.NewClient(cfg.NVDAPIKey),
		circl.NewClient(),
		binaryedge.NewClient(cfg.BinaryEdgeAPIKey),
		criminalip.NewClient(cfg.CriminalIPAPIKey),
		pulsedive.NewClient(cfg.PulsediveAPIKey),
		threatminer.NewClient(""),
		emailrep.NewClient(cfg.EmailRepAPIKey),
		vulners.NewClient(cfg.VulnersAPIKey),
		ipasnhistory.NewClient(""),
		hybridanalysis.NewClient(cfg.HybridAnalysisAPIKey),
		malshare.NewClient(cfg.MalshareAPIKey),
		malwarebazaar.NewClient(cfg.MalwareBazaarAPIKey),
		ssllabs.NewClient(),
	}
	for _, a := range adapters {
		byCode[a.Code()] = a
	}
	return &Registry{adapters: adapters, byCode: byCode}
}

// AdaptersForType returns adapters that support the given indicator type (e.g. ip, domain, url).
func (r *Registry) AdaptersForType(t string) []providerapi.Adapter {
	var out []providerapi.Adapter
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
func (r *Registry) AdapterByCode(code string) providerapi.Adapter {
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
