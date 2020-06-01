package perm

import (
	"github.com/subiz/header"
	"github.com/subiz/header/common"
	"strings"
)

// Contains definition of all subiz oauth scopes
// DO NOT modify these values in runtime
var SCOPEM = map[string]common.Scope{
	"all": common.Scope{
		Description:    "all permissions",
		ReviewRequired: true,
		Permission:     &Base,
	},
	"bot": common.Scope{
		ReviewRequired: true,
		Permission: &common.Permission{
			Account:               ToPerm("u:r"),
			Agent:                 ToPerm("u:r"),
			AgentGroup:            ToPerm("u:r"),
			Rule:                  ToPerm("u:r"),
			Conversation:          ToPerm("u:-ru-"),
			Integration:           ToPerm("u:r"),
			Tag:                   ToPerm("u:r"),
			Widget:                ToPerm("u:r"),
			Subscription:          ToPerm("u:r"),
			User:                  ToPerm("u:r"),
			Ping:                  ToPerm("u:crud a:crud"),
			Attribute:             ToPerm("u:r"),
			Content:               ToPerm("u:r"),
			Pipeline:              ToPerm("u:r"),
			Currency:              ToPerm("u:r"),
			ServiceLevelAgreement: ToPerm("u:r"),
			MessageTemplate:       ToPerm("u:r"),
		},
		AvailableEvents: []string{
			header.RealtimeType_message_sent.String(),
			header.RealtimeType_conversation_state_updated.String(),
			header.RealtimeType_conversation_joined.String(),
			header.RealtimeType_conversation_left.String(),
			header.RealtimeType_conversation_tagged.String(),
			header.RealtimeType_conversation_untagged.String(),
			header.RealtimeType_conversation_typing.String(),
			header.RealtimeType_message_received.String(),
			header.RealtimeType_message_ack.String(),
			header.RealtimeType_message_seen.String(),
			header.RealtimeType_conversation_postbacked.String(),
		},
	},
	"connector": common.Scope{
		ReviewRequired: true,
		Permission: &common.Permission{
			Account:         ToPerm("u:r"),
			Agent:           ToPerm("u:r a:r"), // list all agent in account
			AgentGroup:      ToPerm("u:r a:r"), // list all group in account
			Conversation:    ToPerm("u:cru- a:cru-"),
			Tag:             ToPerm("a:r"),
			WhitelistIp:     ToPerm("a:r"),
			WhitelistUser:   ToPerm("a:r"),
			WhitelistDomain: ToPerm("a:r"),
			User:            ToPerm("a:r"),
			Ping:            ToPerm("u:crud a:crud"),
			Attribute:       ToPerm("a:r"),
			MessageTemplate: ToPerm("a:r"),
		},
		AvailableEvents: []string{
			header.RealtimeType_message_sent.String(),
			header.RealtimeType_conversation_state_updated.String(),
			header.RealtimeType_conversation_joined.String(),
			header.RealtimeType_conversation_left.String(),
			header.RealtimeType_message_received.String(),
			header.RealtimeType_message_ack.String(),
			header.RealtimeType_message_seen.String(),
		},
	},
}

// CanListenEvent tells whether a client with scopes can receive event_type event
func CanListenEvent(scopes []string, event_type string) bool {
	event_type = strings.TrimSpace(strings.ToLower(event_type))
	if event_type == "" {
		return false
	}
	for _, scopeStr := range scopes {
		scope, ok := SCOPEM[scopeStr]
		if !ok {
			scopeStr = strings.TrimSpace(strings.ToLower(scopeStr))
			scope, ok = SCOPEM[scopeStr]
			if !ok {
				continue
			}
		}

		for _, ae := range scope.AvailableEvents {
			if ae == event_type {
				return true
			}
		}
	}
	return false
}
