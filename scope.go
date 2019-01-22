package perm

import "github.com/subiz/header/auth"

// Contains definition of all subiz oauth scopes
// DO NOT modify these values in runtime
var SCOPEM = map[string]auth.Scope{
	"all": auth.Scope{
		Description:    "all permissions",
		ReviewRequired: true,
		Permission:     &Base,
	},
	"bot": auth.Scope{
		ReviewRequired: true,
		Permission: &auth.Permission{
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
		}},
	"connector": auth.Scope{
		ReviewRequired: true,
		Permission: &auth.Permission{
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
		}},
}
