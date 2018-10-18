package perm

import (
	"reflect"
	"runtime"
	"strings"

	"git.subiz.net/errors"
	"git.subiz.net/header/auth"
	cpb "git.subiz.net/header/common"
)

func getPerm(r string, num int32) int32 {
	if r == "u" {
		num &= 0x000F
	} else if r == "a" {
		num &= 0x00F0
		num = num >> 4
	} else if r == "s" {
		num &= 0x0F00
		num = num >> 8
	} else {
		num = 0
	}
	return num
}

func filterSinglePerm(r string, num int32) int32 {
	if r == "u" {
		num &= 0x000F
	} else if r == "a" {
		num &= 0x00F0
	} else if r == "s" {
		num &= 0x0F00
	} else {
		num = 0
	}
	return num
}

func filterPerm(r string, p *auth.Permission) *auth.Permission {
	if p == nil {
		p = &auth.Permission{}
	}
	ret := &auth.Permission{}
	var sp = reflect.ValueOf(*p)
	var sret = reflect.ValueOf(ret).Elem()

	for i := 0; i < sp.NumField(); i++ {
		num, ok := sp.Field(i).Interface().(int32)
		if !ok {
			continue
		}

		num = filterSinglePerm(r, num)
		sret.Field(i).Set(reflect.ValueOf(num))

	}
	return ret
}

func findPerm(p reflect.Value, name string) int32 {
	for i := 0; i < p.NumField(); i++ {
		if p.Type().Field(i).Name == name {
			num, _ := p.Field(i).Interface().(int32)
			return num
		}
	}
	return -1
}

func check(funcname string, cred *auth.Credential, accid string, agids []string) error {
	if strings.TrimSpace(accid) == "" {
		return errors.New(400, cpb.E_missing_account_id)
	}
	funcname = strings.TrimSpace(funcname)
	if len(funcname) < 5 {
		return errors.New(400, cpb.E_access_deny, "wrong perm check: "+funcname)
	}

	funcname = funcname[5:] // strip check
	p := ""
	prop := ""
	if strings.HasPrefix(strings.ToLower(funcname), "create") {
		p = "c"
		prop = funcname[6:]
	} else if strings.HasPrefix(strings.ToLower(funcname), "read") {
		p = "r"
		prop = funcname[4:]
	} else if strings.HasPrefix(strings.ToLower(funcname), "update") {
		p = "u"
		prop = funcname[6:]
	} else if strings.HasPrefix(strings.ToLower(funcname), "delete") {
		p = "d"
		prop = funcname[6:]
	} else {
		return errors.New(400, cpb.E_access_deny, "wrong perm check: "+funcname)
	}

	perm := cred.GetPerm()
	if perm == nil {
		perm = &auth.Permission{}
	}
	sperm := reflect.ValueOf(*perm)
	bperm := reflect.ValueOf(MakeBase())

	sp := findPerm(sperm, prop)
	bp := findPerm(bperm, prop)

	ismine := cred.GetAccountId() == accid && contains(cred.GetIssuer(), agids)
	isaccount := cred.GetAccountId() == accid

	return C(p, bp, sp, ismine, isaccount)
}

func strPermToInt(p string) int32 {
	out := int32(0)
	if strings.Contains(p, "c") {
		out |= 8
	}

	if strings.Contains(p, "r") {
		out |= 4
	}

	if strings.Contains(p, "u") {
		out |= 2
	}

	if strings.Contains(p, "d") {
		out |= 1
	}
	return out
}

func Merge(a, b *auth.Permission) *auth.Permission {
	if a == nil {
		a = &auth.Permission{}
	}

	if b == nil {
		b = &auth.Permission{}
	}

	ret := &auth.Permission{}
	var sa = reflect.ValueOf(*a)
	var sb = reflect.ValueOf(*b)
	var sret = reflect.ValueOf(ret).Elem()

	for i := 0; i < sa.NumField(); i++ {
		numa, _ := sa.Field(i).Interface().(int32)
		numb, _ := sb.Field(i).Interface().(int32)
		func() {
			defer func() {
				recover()
			}()
			sret.Field(i).Set(reflect.ValueOf(numa | numb))
		}()
	}
	return ret
}

func ToPerm(p string) int32 {
	rawperms := strings.Split(strings.TrimSpace(p), " ")
	um, am, sm := "", "", ""
	for _, perm := range rawperms {
		perm = strings.TrimSpace(strings.ToLower(perm))
		if len(perm) < 2 {
			continue
		}

		if perm[0] == 'u' {
			um += perm[1:]
		} else if perm[0] == 'a' {
			am += perm[1:]
		} else if perm[0] == 's' {
			sm += perm[1:]
		} else {
			continue
		}
	}
	return strPermToInt(um) | strPermToInt(am)<<4 | strPermToInt(sm)<<8
}

func IntersectPermission(a, b *auth.Permission) *auth.Permission {
	var ret = &auth.Permission{}
	if a == nil {
		a = &auth.Permission{}
	}

	if b == nil {
		b = &auth.Permission{}
	}

	var sa = reflect.ValueOf(*a)
	var sb = reflect.ValueOf(*b)
	var sret = reflect.ValueOf(ret).Elem()

	for i := 0; i < sa.NumField(); i++ {
		fa, ok := sa.Field(i).Interface().(int32)
		if !ok {
			continue
		}
		fb, ok := sb.Field(i).Interface().(int32)
		if !ok {
			continue
		}

		faandfb := fa & fb
		sret.Field(i).Set(reflect.ValueOf(faandfb))
	}
	return ret
}

func MakeBase() auth.Permission {
	return auth.Permission{
		Account:            ToPerm("o:-r-- u:---- a:cru- s:cru-"),
		Agent:              ToPerm("o:-r-- u:-ru- a:crud s:-r-d"),
		AgentPassword:      ToPerm("o:---- u:cru- a:c-u- s:cru-"),
		Permission:         ToPerm("o:---- u:-r-- a:-ru- s:-ru-"),
		AgentGroup:         ToPerm("o:---- u:---- a:crud s:-r--"),
		Segmentation:       ToPerm("o:---- u:crud a:crud s:-r--"),
		Client:             ToPerm("o:---- u:---- a:---- s:-r--"),
		Rule:               ToPerm("o:---- u:---- a:crud s:-r--"),
		Conversation:       ToPerm("o:---- u:cru- a:-ru- s:cr--"),
		Integration:        ToPerm("o:---- u:---- a:crud s:cr--"),
		CannedResponse:     ToPerm("o:---- u:crud a:crud s:cr--"),
		Tag:                ToPerm("o:---- u:---- a:crud s:cr--"),
		WhitelistIp:        ToPerm("o:---- u:---- a:crud s:cr--"),
		WhitelistUser:      ToPerm("o:---- u:---- a:crud s:cr--"),
		WhitelistDomain:    ToPerm("o:---- u:---- a:crud s:cr--"),
		Widget:             ToPerm("o:---- u:---- a:cru- s:cr--"),
		Subscription:       ToPerm("o:---- u:---- a:cru- s:crud"),
		Invoice:            ToPerm("o:---- u:---- a:-r-- s:cru-"),
		PaymentMethod:      ToPerm("o:---- u:---- a:crud s:cru-"),
		Bill:               ToPerm("o:---- u:---- a:-r-- s:cru-"),
		PaymentLog:         ToPerm("o:---- u:---- a:-r-- s:-r--"),
		PaymentComment:     ToPerm("o:---- u:---- a:---- s:cr--"),
		User:               ToPerm("o:---- u:crud a:crud s:cru-"),
		Automation:         ToPerm("o:-r-- u:---- a:crud s:cr--"),
		Ping:               ToPerm("o:---- u:crud a:crud s:----"),
		Attribute:          ToPerm("o:---- u:---- a:crud s:-r--"),
		AgentNotification:  ToPerm("o:---- u:crud a:---- s:-r--"),
		ConversationExport: ToPerm("o:---- u:---- a:c--- s:----"),
		ConversationReport: ToPerm("o:---- u:---- a:-r-- s:-r--"),
		Content:            ToPerm("o:-ru- u:---- a:crud s:-r--"),
	}
}

func contains(s string, ss []string) bool {
	for _, i := range ss {
		if i == s {
			return true
		}
	}
	return false
}

func C(p string, rperm, callerperm int32, ismine, isaccount bool) error {
	rp := strPermToInt(p)
	if ismine {
		rperm = getPerm("u", rperm)
		callerperm = getPerm("u", callerperm)
	} else if isaccount {
		rperm = getPerm("a", rperm)
		callerperm = getPerm("a", callerperm)
	} else {
		rperm = getPerm("s", rperm)
		callerperm = getPerm("s", callerperm)
	}
	rperm = rperm & rp

	if rperm == 0 {
		return errors.New(400, cpb.E_access_deny, "access to resource is prohibited,", p, rperm)
	}

	if rperm&callerperm != rperm {
		return errors.New(400, cpb.E_access_deny, "not enough permission, need %d, got %d", rperm, callerperm)
	}

	return nil
}

func getCurrentFunc() string {
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	name := runtime.FuncForPC(pc[0]).Name()
	ns := strings.Split(name, ".")
	if len(ns) == 0 {
		return ""
	}
	return ns[len(ns)-1]
}

func CheckCreateAccount(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAccount(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAccount(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAccount(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAgent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAgent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAgent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAgent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAgentPassword(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAgentPassword(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAgentPassword(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAgentPassword(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreatePermission(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadPermission(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdatePermission(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeletePermission(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAgentGroup(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAgentGroup(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAgentGroup(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAgentGroup(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateSegmentation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadSegmentation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateSegmentation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteSegmentation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateClient(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadClient(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateClient(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteClient(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateRule(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadRule(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateRule(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteRule(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateConversation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadConversation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateConversation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteConversation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateIntegration(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadIntegration(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateIntegration(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteIntegration(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateCannedResponse(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadCannedResponse(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateCannedResponse(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteCannedResponse(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateTag(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadTag(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateTag(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteTag(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateWhitelistIp(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadWhitelistIp(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateWhitelistIp(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteWhitelistIp(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateWhitelistUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadWhitelistUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateWhitelistUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteWhitelistUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadWhitelistDomain(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateWhitelistDomain(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateWhitelistDomain(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteWhitelistDomain(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateWidget(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadWidget(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateWidget(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteWidget(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateSubscription(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadSubscription(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateSubscription(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteSubscription(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateInvoice(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadInvoice(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateInvoice(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteInvoice(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreatePaymentMethod(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadPaymentMethod(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdatePaymentMethod(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeletePaymentMethod(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateBill(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadBill(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateBill(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteBill(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreatePaymentLog(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadPaymentLog(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdatePaymentLog(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeletePaymentLog(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreatePaymentComment(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadPaymentComment(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdatePaymentComment(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeletePaymentComment(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteUser(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAutomation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAutomation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAutomation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAutomation(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAttribute(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAttribute(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAttribute(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAttribute(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateAgentNotification(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadAgentNotification(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateAgentNotification(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteAgentNotification(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateConversationExport(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadConversationReport(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckCreateContent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckReadContent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckUpdateContent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
func CheckDeleteContent(cred *auth.Credential, acid string, agids ...string) error {
	return check(getCurrentFunc(), cred, acid, agids)
}
