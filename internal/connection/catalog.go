package connection

import "cove/internal/config"

// Service is a catalog entry whose values deliberately mirror the historical
// seed stanzas. The catalog is the source for generated connections; secrets
// are supplied separately and never live here.
type Service struct {
	Name       string
	SecretFile string
	Stanza     config.InjectStanza
	Try        string
}

var services = map[string]Service{
	"openai":      {"openai", "openai-api-key", config.InjectStanza{Name: "openai", Host: "api.openai.com", HeaderName: "Authorization", HeaderTemplate: "Bearer {secret}", DummyEnv: "OPENAI_API_KEY", DummyValue: "cove-dummy-openai-ask-the-human-to-run-cove-add-openai", StripHeaders: []string{"x-api-key"}, BaseURLEnv: "OPENAI_BASE_URL", BaseURLValue: "https://api.openai.com/v1"}, "try: cove claude"},
	"kimi":        {"kimi", "kimi-api-key", config.InjectStanza{Name: "kimi", Host: "api.moonshot.cn", HeaderName: "Authorization", HeaderTemplate: "Bearer {secret}", DummyEnv: "KIMI_API_KEY", DummyValue: "cove-dummy-kimi-ask-the-human-to-run-cove-add-kimi", BaseURLEnv: "KIMI_BASE_URL", BaseURLValue: "http://127.0.0.1:0"}, "try: cove claude"},
	"gemini":      {"gemini", "gemini-api-key", config.InjectStanza{Name: "gemini", Host: "generativelanguage.googleapis.com", HeaderName: "x-goog-api-key", HeaderTemplate: "{secret}", DummyEnv: "GEMINI_API_KEY", DummyValue: "cove-dummy-gemini-ask-the-human-to-run-cove-add-gemini", BaseURLEnv: "GOOGLE_GEMINI_BASE_URL", BaseURLValue: "https://generativelanguage.googleapis.com"}, "try: cove claude"},
	"huggingface": {"huggingface", "hf-token", config.InjectStanza{Name: "huggingface", Host: "huggingface.co", HeaderName: "Authorization", HeaderTemplate: "Bearer {secret}", DummyEnv: "HF_TOKEN", DummyValue: "cove-dummy-huggingface-ask-the-human-to-run-cove-add-huggingface"}, "try: cove claude"},
}

func githubPAT(repo []string) (config.InjectStanza, config.InjectStanza) {
	secret := "file:" + config.ConfigDir() + "/secrets/github-pat"
	return config.InjectStanza{Name: "github-api", Host: "api.github.com", HeaderName: "Authorization", HeaderTemplate: "Bearer {secret}", Secret: secret, DummyEnv: "GH_TOKEN", DummyValue: "cove-dummy-github-ask-the-human-to-run-cove-add-github"},
		config.InjectStanza{Name: "github", Host: "github.com", Transform: "github-basic", HeaderName: "Authorization", BasicUsername: "x-access-token", Secret: secret, GitHubRepositories: repo, AllowedMethods: []string{"GET", "POST"}, DummyEnv: "GH_TOKEN", DummyValue: "cove-dummy-github-ask-the-human-to-run-cove-add-github"}
}
