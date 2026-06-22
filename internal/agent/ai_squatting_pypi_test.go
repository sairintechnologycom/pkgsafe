package agent

import "testing"

func TestCheckAISquattingEcosystemPyPI(t *testing.T) {
	if !CheckAISquattingEcosystem("pypi", "langchain-openai-wrapper-pro", "", nil, true, 1, true) {
		t.Fatal("expected PyPI AI package squatting candidate")
	}
}
