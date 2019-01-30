package perm

import (
	"testing"
)

func TestCanListenEvent(t *testing.T) {
	tcs := []struct {
		desc   string
		scopes []string
		event  string
		expect bool
	}{
		{"1", []string{}, "a", false},
		{"2", nil, "b", false},
		{"3", []string{"bot"}, "conversation_untagged", true},
		{"3", []string{"bot  "}, " Conversation_untagged ", true},
		{"3", []string{"connnector"}, " Conversation_untagged ", false},
		{"3", []string{"bot  "}, " Conversation_untagged ", true},
		{"3", []string{"connnector", "bot"}, " Conversation_untagged ", true},
	}

	for _, tc := range tcs {
		out := CanListenEvent(tc.scopes, tc.event)
		if out != tc.expect {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, out)
		}
	}
}
