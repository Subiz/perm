package perm

import (
	"github.com/subiz/header/auth"
)

func MethodToPerm(m *auth.Method) *auth.Permission {
	if m == nil {
		m = &auth.Method{}
	}
	p := &auth.Permission{}

	if m.Ping {
		p.Ping = ToPerm("u:crud a:crud")
	}
	if m.UpdateSegmentation {
		p.Segmentation |= ToPerm("a:u")
	}
	if m.ReadSegmentation {
		p.Segmentation |= ToPerm("a:r")
	}
	if m.DeleteSegmentation {
		p.Segmentation |= ToPerm("a:d")
	}
	if m.CreateSegmentation {
		p.Segmentation |= ToPerm("a:c")
	}
	if m.InviteAgent {
		p.Agent |= ToPerm("a:c")
	}
	if m.UpdateAgent {
		p.Agent |= ToPerm("u:u")
	}
	if m.UpdateAgents {
		p.Agent |= ToPerm("a:u")
	}
	if m.ReadAgent {
		p.Agent |= ToPerm("u:r")
	}
	if m.ReadAgents {
		p.Agent |= ToPerm("a:r")
	}
	if m.ResetPassword { // 11
		p.AgentPassword |= ToPerm("u:u")
	}
	if m.UpdateAgentsPermission {
		p.Permission |= ToPerm("a:u")
	}
	if m.ReadAgentPermission {
		p.Permission |= ToPerm("u:r")
	}
	if m.UpdateAgentsState {
		p.Agent |= ToPerm("a:d")
	}
	if m.ReadAccount {
		p.Account |= ToPerm("u:crud a:crud")
	}
	if m.CreateAgentGroup {
		p.AgentGroup |= ToPerm("a:c")
	}
	if m.DeleteAgentGroup {
		p.AgentGroup |= ToPerm("a:d")
	}
	if m.ReadAgentGroup {
		p.AgentGroup |= ToPerm("a:r")
	}
	if m.UpdateAgentGroup {
		p.AgentGroup |= ToPerm("a:u")
	}
	if m.UpdatePlan {
		p.Subscription |= ToPerm("u:u a:u")
	}
	if m.UpdateAccountInfomation { // 10
		p.Account |= ToPerm("a:u")
	}
	if m.ReadClient {
		p.Client |= ToPerm("u:r a:r")
	}
	if m.UpdateClient {
		p.Client |= ToPerm("u:u a:u")
	}
	if m.DeleteClient {
		p.Client |= ToPerm("u:d a:d")
	}
	if m.CreateClient {
		p.Client |= ToPerm("u:c a:c")
	}
	if m.ReadRule {
		p.Rule |= ToPerm("a:r")
	}
	if m.CreateRule {
		p.Rule |= ToPerm("a:c")
	}
	if m.DeleteRule {
		p.Rule |= ToPerm("a:d")
	}
	if m.UpdateRule {
		p.Rule |= ToPerm("a:u")
	}
	if m.StartConversation {
		p.Conversation |= ToPerm("u:c")
	}
	if m.ReadConversation {
		p.Conversation |= ToPerm("u:r")
	}
	if m.ExportConversations {
		p.Conversation |= ToPerm("a:u")
	}
	if m.ReadTeammatesConversations {
		p.Conversation |= ToPerm("a:r")
	}
	if m.SendMessage { // 13
		p.Conversation |= ToPerm("u:u")
	}
	if m.IntegrateConnector {
		p.Integration |= ToPerm("a:cud")
	}
	if m.ReadUserEmail {
		p.Integration |= ToPerm("u:r a:r")
	}
	if m.ReadUserFacebookId {
		p.Integration |= ToPerm("u:r a:r")
	}
	if m.ReadUserPhones {
		p.Integration |= ToPerm("u:r a:r")
	}
	if m.ReadUserWidgetSetting {
		p.Integration |= ToPerm("u:r a:r")
	}
	if m.ReadTag {
		p.Tag |= ToPerm("a:r")
	}
	if m.UpdateTag {
		p.Tag |= ToPerm("a:cu")
	}
	if m.DeleteTag {
		p.Tag |= ToPerm("a:d")
	}
	if m.UpdateWidgetSetting {
		p.Widget |= ToPerm("a:u")
	}
	if m.CreateWhitelistDomain {
		p.WhitelistDomain |= ToPerm("a:cu")
	}
	if m.CreateWhitelistIp {
		p.WhitelistIp |= ToPerm("a:cu")
	}
	if m.CreateWhitelistUser {
		p.WhitelistUser |= ToPerm("a:cu")
	}
	if m.DeleteWhitelistDomain {
		p.WhitelistDomain |= ToPerm("a:d")
	}
	if m.DeleteWhitelistIp {
		p.WhitelistIp |= ToPerm("a:d")
	}
	if m.DeleteWhitelistUser {
		p.WhitelistUser |= ToPerm("a:d")
	}
	if m.ReadWhitelistIp {
		p.WhitelistIp |= ToPerm("a:r")
	}
	if m.ReadWhitelistDomain {
		p.WhitelistDomain |= ToPerm("a:r")
	}
	if m.ReadWhitelistUser {
		p.WhitelistUser |= ToPerm("a:r")
	}
	if m.PurchaseService { // 19
		p.Subscription |= ToPerm("a:u")
	}
	if m.UpdatePaymentMethod {
		p.Subscription |= ToPerm("a:u")
	}
	if m.PayInvoice {
		p.Subscription |= ToPerm("a:u")
		p.Invoice |= ToPerm("a:c")
	}
	if m.UpdateBillingCycle {
		p.Subscription |= ToPerm("a:u")
	}
	if m.ReadInvoice {
		p.Invoice |= ToPerm("a:r")
	}
	if m.ReadSubscription {
		p.Subscription |= ToPerm("a:r")
	}
	if m.ReadAttribute {
		p.Attribute |= ToPerm("a:r")
	}
	if m.CreateAttribute {
		p.Attribute |= ToPerm("a:c")
	}
	if m.UpdateAttribute {
		p.Attribute |= ToPerm("a:u")
	}
	if m.DeleteAttribute {
		p.Attribute |= ToPerm("a:d")
	}
	if m.ReadAllAccounts {
		p.Account |= ToPerm("s:r")
	}
	if m.ReadAllAgents {
		p.Agent |= ToPerm("s:r")
	}
	if m.ReadPaymentComments {
		p.PaymentComment |= ToPerm("s:r")
	}
	if m.AddPaymentComments {
		p.PaymentComment |= ToPerm("s:c")
	}
	if m.ReadAllBills {
		p.Bill |= ToPerm("s:r")
	}
	if m.WriteAllInvoices {
		p.Invoice |= ToPerm("s:cu")
	}
	if m.ReadAllInvoices {
		p.Invoice |= ToPerm("s:r")
	}
	if m.PurchaseAllServices {
		p.Subscription |= ToPerm("s:u")
	}
	if m.ReadAllSubscriptions {
		p.Subscription |= ToPerm("s:r")
	}
	if m.AddCredit {
		p.Subscription |= ToPerm("s:u")
	}
	if m.UpdateAllSubscriptions {
		p.Invoice |= ToPerm("s:c")
		p.Subscription |= ToPerm("s:u")
	}
	if m.PayAllInvoices {
		p.Invoice |= ToPerm("s:u")
	}
	if m.TransferMoney {
		p.Bill |= ToPerm("s:c")
	}
	if m.ReadAllLogs {
		p.PaymentLog |= ToPerm("s:r")
	}
	if m.GrantAllPerm {
		p.Permission |= ToPerm("s:u")
	}
	return p
}
