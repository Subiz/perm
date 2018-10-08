package perm

import (
	"git.subiz.net/header/auth"
)

func GetAccountSettingPerm() *auth.Permission {
	return &auth.Permission{
		Account:           ToPerm("a:cru-"),
		Agent:             ToPerm("a:crud"),
		Permission:        ToPerm("a:-ru-"),
		AgentGroup:        ToPerm("a:crud"),
		Segmentation:      ToPerm("a:crud"),
		Client:            ToPerm("a:crud"),
		Rule:              ToPerm("a:crud"),
		Conversation:      ToPerm("a:--u-"),
		Integration:       ToPerm("a:crud"),
		CannedResponse:    ToPerm("a:crud"),
		Tag:               ToPerm("a:crud"),
		WhitelistIp:       ToPerm("a:crud"),
		WhitelistUser:     ToPerm("a:crud"),
		WhitelistDomain:   ToPerm("a:crud"),
		Widget:            ToPerm("a:cru-"),
		Subscription:      ToPerm(""),
		Invoice:           ToPerm(""),
		PaymentMethod:     ToPerm(""),
		Bill:              ToPerm(""),
		PaymentLog:        ToPerm(""),
		PaymentComment:    ToPerm(""),
		User:              ToPerm("a:crud"),
		Automation:        ToPerm("a:crud"),
		Ping:              ToPerm("a:crud"),
		Attribute:         ToPerm("a:crud"),
		AgentNotification: ToPerm(""),
	}
}

func GetAccountManagePerm() *auth.Permission {
	return Merge(GetAccountSettingPerm(), &auth.Permission{
		Subscription:   ToPerm("a:cru-"),
		Invoice:        ToPerm("a:-r--"),
		PaymentMethod:  ToPerm("a:crud"),
		Bill:           ToPerm("a:-r--"),
		PaymentLog:     ToPerm("a:-r--"),
		PaymentComment: ToPerm(""),
	})
}

func GetOwnerPerm() *auth.Permission {
	pe := Merge(GetAccountManagePerm(), GetAccountSettingPerm())
	pe = Merge(pe, &auth.Permission{Conversation: ToPerm("a:-r--")})
	pe.ConversationExport = ToPerm("a:cr--")
	pe.ConversationReport = ToPerm("a:-r--")
	return pe
}

func GetAgentPerm() *auth.Permission {
	return &auth.Permission{
		Account:           ToPerm("a:-r--"),
		Agent:             ToPerm("u:-ru- a:-r--"),
		AgentPassword:     ToPerm("u:cru-"),
		Permission:        ToPerm("u:-r-- a:-r--"),
		AgentGroup:        ToPerm("a:-r--"),
		Segmentation:      ToPerm("u:crud a:-r--"),
		Client:            ToPerm(""),
		Rule:              ToPerm("a:-r--"),
		Conversation:      ToPerm("u:cru- a:-r--"),
		Integration:       ToPerm("a:-r--"),
		CannedResponse:    ToPerm("u:crud a:-r--"),
		Tag:               ToPerm("a:-r--"),
		WhitelistIp:       ToPerm("a:-r--"),
		WhitelistUser:     ToPerm("a:-r--"),
		WhitelistDomain:   ToPerm("a:-r--"),
		Widget:            ToPerm("a:-r--"),
		Subscription:      ToPerm("a:-r--"),
		Invoice:           ToPerm(""),
		PaymentMethod:     ToPerm(""),
		Bill:              ToPerm(""),
		PaymentLog:        ToPerm(""),
		PaymentComment:    ToPerm(""),
		User:              ToPerm("u:crud a:-r--"),
		Automation:        ToPerm("a:-r--"),
		Ping:              ToPerm("u:cru- a:cru-"),
		Attribute:         ToPerm("a:-r--"),
		AgentNotification: ToPerm("u:crud"),
	}
}
