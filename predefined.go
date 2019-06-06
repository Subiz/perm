package perm

import "github.com/subiz/header/common"

func GetAccountSettingPerm() *common.Permission {
	return Merge(GetAgentPerm(), &common.Permission{
		Account:               ToPerm("a:cru-"),
		Agent:                 ToPerm("a:crud"),
		Permission:            ToPerm("a:-ru-"),
		AgentGroup:            ToPerm("a:crud"),
		Segmentation:          ToPerm("a:crud"),
		Client:                ToPerm("a:crud"),
		Rule:                  ToPerm("a:crud"),
		Conversation:          ToPerm("a:--u-"),
		Integration:           ToPerm("a:crud"),
		CannedResponse:        ToPerm("a:crud"),
		Tag:                   ToPerm("a:crud"),
		WhitelistIp:           ToPerm("a:crud"),
		WhitelistUser:         ToPerm("a:crud"),
		WhitelistDomain:       ToPerm("a:crud"),
		Widget:                ToPerm("a:cru-"),
		Subscription:          ToPerm(""),
		Invoice:               ToPerm(""),
		PaymentMethod:         ToPerm(""),
		Bill:                  ToPerm(""),
		PaymentLog:            ToPerm(""),
		PaymentComment:        ToPerm(""),
		User:                  ToPerm("a:crud"),
		Automation:            ToPerm("a:crud"),
		Ping:                  ToPerm("a:crud"),
		Attribute:             ToPerm("a:crud"),
		AgentNotification:     ToPerm(""),
		Pipeline:              ToPerm("a:crud"),
		Currency:              ToPerm("a:crud"),
		ServiceLevelAgreement: ToPerm("a:crud"),
		MessageTemplate:       ToPerm("a:crud"),
	})
}

func GetAccountManagePerm() *common.Permission {
	return Merge(GetAccountSettingPerm(), &common.Permission{
		Subscription:   ToPerm("a:cru-"),
		Invoice:        ToPerm("a:-r--"),
		PaymentMethod:  ToPerm("a:crud"),
		Bill:           ToPerm("a:-r--"),
		PaymentLog:     ToPerm("a:-r--"),
		PaymentComment: ToPerm(""),
	})
}

func GetOwnerPerm() *common.Permission {
	pe := Merge(GetAccountManagePerm(), &common.Permission{Conversation: ToPerm("a:-r--")})
	pe.ConversationExport = ToPerm("a:cr--")
	pe.ConversationReport = ToPerm("a:-r--")
	return pe
}

func GetAgentPerm() *common.Permission {
	return &common.Permission{
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
		Content:           ToPerm("a:crud"),
		MessageTemplate:   ToPerm("u:crud a:-r--"),
	}
}
