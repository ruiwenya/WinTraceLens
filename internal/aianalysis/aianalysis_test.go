package aianalysis

import "testing"

func TestChatEndpointAppendsChatCompletions(t *testing.T) {
	endpoint, err := chatEndpoint("https://dashscope.aliyuncs.com/compatible-mode/v1")
	if err != nil {
		t.Fatalf("chatEndpoint error: %v", err)
	}
	want := "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
	if endpoint != want {
		t.Fatalf("endpoint = %q, want %q", endpoint, want)
	}
}

func TestChatEndpointKeepsFullEndpoint(t *testing.T) {
	endpoint, err := chatEndpoint("https://api.deepseek.com/chat/completions")
	if err != nil {
		t.Fatalf("chatEndpoint error: %v", err)
	}
	if endpoint != "https://api.deepseek.com/chat/completions" {
		t.Fatalf("endpoint = %q", endpoint)
	}
}

func TestNormalizeSectionsDefaultsAndDedupes(t *testing.T) {
	sections := normalizeSections([]string{"processes", "bad", "processes", "security"})
	if len(sections) != 2 {
		t.Fatalf("sections len = %d, want 2", len(sections))
	}
	if sections[0] != sectionProcesses || sections[1] != sectionSecurity {
		t.Fatalf("sections = %#v", sections)
	}
	if len(normalizeSections(nil)) == 0 {
		t.Fatalf("default sections should not be empty")
	}
}

func TestNormalizeMessagesRequiresUserLast(t *testing.T) {
	_, err := normalizeMessages([]Message{{Role: "assistant", Content: "done"}})
	if err == nil {
		t.Fatalf("normalizeMessages should reject assistant-only tail")
	}

	messages, err := normalizeMessages([]Message{
		{Role: "system", Content: "ignored"},
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "answer"},
		{Role: "user", Content: "follow up"},
	})
	if err != nil {
		t.Fatalf("normalizeMessages error: %v", err)
	}
	if len(messages) != 3 {
		t.Fatalf("message count = %d, want 3", len(messages))
	}
	if messages[len(messages)-1].Role != "user" {
		t.Fatalf("last role = %q", messages[len(messages)-1].Role)
	}
}

func TestNormalizeSessionStateKeepsRuntimeAPIKeys(t *testing.T) {
	state := NormalizeSessionState(SessionState{
		Messages: []Message{{Role: "user", Content: "hello"}},
		Summary: AnalyzeResponse{
			Answer:   "should not be persisted",
			Endpoint: "https://api.example.test/v1/chat/completions",
		},
		APIKeys: map[string]string{
			" DeepSeek ": "  sk-test  ",
			"openai":     "",
		},
		Settings: SessionSettings{
			Provider: "deepseek",
			Sections: []string{"loghealth"},
		},
	})
	if state.Summary.Answer != "" {
		t.Fatalf("summary answer should be cleared")
	}
	if state.APIKeys["deepseek"] != "sk-test" {
		t.Fatalf("deepseek key was not normalized")
	}
	if _, ok := state.APIKeys["openai"]; ok {
		t.Fatalf("empty api key should be removed")
	}
}
