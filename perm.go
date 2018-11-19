package perm

//go:generate ./gen.sh

import (
	"reflect"
	"strings"

	"git.subiz.net/errors"
	"git.subiz.net/header/auth"
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

func C2(p string, base, callerperm int32, cred *auth.Credential, accid string, agids ...string) error {
	ismine := cred.GetAccountId() == accid && contains(cred.GetIssuer(), agids)
	isaccount := cred.GetAccountId() == accid

	rp := strPermToInt(p)
	if ismine {
		base = getPerm("u", base)
		callerperm = getPerm("u", callerperm)
	} else if isaccount {
		base = getPerm("a", base)
		callerperm = getPerm("a", callerperm)
	} else {
		base = getPerm("s", base)
		callerperm = getPerm("s", callerperm)
	}
	base = base & rp

	if base == 0 {
		return errors.New(400, errors.E_access_deny, "access to resource is prohibited,", p, base)
	}

	if base&callerperm != base {
		return errors.New(400, errors.E_access_deny, "not enough permission, need %d, got %d", base, callerperm)
	}

	return nil
}

func checkCreateCurrency(cred *auth.Credential, accid string, agids ...string) error {
	p := "c"
	callerperm := cred.GetPerm().GetCurrency()
	base := Base.GetCurrency()
	return C2(p, base, callerperm, cred, accid, agids...)
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

var Base = auth.Permission{
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
	Pipeline:           ToPerm("o:---- u:---- a:crud s:-r--"),
	Currency:           ToPerm("o:---- u:---- a:crud s:-r--"),
}

func MakeBase() auth.Permission { return Base }

func contains(s string, ss []string) bool {
	for _, i := range ss {
		if i == s {
			return true
		}
	}
	return false
}
