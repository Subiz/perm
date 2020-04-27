package perm

//go:generate ./gen.sh

import (
	"reflect"
	"strings"

	"github.com/subiz/errors"
	"github.com/subiz/header/common"
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

// required: the required permission
func checkPerm(required, callerperm int32, ismine, sameaccount bool) error {
	// check super perm first
	if required&getPerm("s", callerperm) == required {
		return nil
	}

	if !sameaccount {
		return errors.New(400, errors.E_access_deny, "not enought permission")
	}

	// check my resource permission
	if ismine {
		if required&getPerm("u", callerperm) == required {
			return nil
		}
	}

	if required&getPerm("a", callerperm) == required {
		return nil
	}

	return errors.New(400, errors.E_access_deny, "not enough permission")
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

// Intersect returns a strongest permission which both a and b contains
func Intersect(a, b *common.Permission) *common.Permission {
	if a == nil {
		a = &common.Permission{}
	}

	if b == nil {
		b = &common.Permission{}
	}

	ret := &common.Permission{}
	var sa = reflect.ValueOf(*a)
	var sb = reflect.ValueOf(*b)
	var sret = reflect.ValueOf(ret).Elem()

	for i := 0; i < sa.NumField(); i++ {
		// only bother exported fields
		if !sa.Field(i).CanInterface() {
			continue
		}

		numa, _ := sa.Field(i).Interface().(int32)
		numb, _ := sb.Field(i).Interface().(int32)
		func() {
			defer func() {
				recover()
			}()
			sret.Field(i).Set(reflect.ValueOf(numa & numb))
		}()
	}
	return ret
}

// Merge returns a new permission which contain a and b
func Merge(a, b *common.Permission) *common.Permission {
	if a == nil {
		a = &common.Permission{}
	}

	if b == nil {
		b = &common.Permission{}
	}

	ret := &common.Permission{}
	var sa = reflect.ValueOf(*a)
	var sb = reflect.ValueOf(*b)
	var sret = reflect.ValueOf(ret).Elem()

	for i := 0; i < sa.NumField(); i++ {
		// only bother exported fields
		if !sa.Field(i).CanInterface() {
			continue
		}

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

// ToPerm converts permission in string representation to integer representation
// examples:
//   ToPerm("u:-ru-")   0x6
//   ToPerm("u:r u:u")  0x6
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

// Base is the biggest possible permission that is valid
// it is often used with IntersectPermission method to correct mal-granted
// permissions
var Base = common.Permission{
	Account:               ToPerm("o:---- u:---- a:cru- s:cru-"),
	Agent:                 ToPerm("o:-r-- u:-ru- a:crud s:-r-d"),
	AgentPassword:         ToPerm("o:---- u:cru- a:c-u- s:cru-"),
	Permission:            ToPerm("o:---- u:-r-- a:-ru- s:-ru-"),
	AgentGroup:            ToPerm("o:---- u:---- a:crud s:-r--"),
	Segmentation:          ToPerm("o:---- u:crud a:crud s:-r--"),
	Client:                ToPerm("o:---- u:---- a:---- s:-r--"),
	Rule:                  ToPerm("o:---- u:---- a:crud s:-r--"),
	Conversation:          ToPerm("o:---- u:cru- a:-ru- s:cr--"),
	Integration:           ToPerm("o:---- u:---- a:crud s:cr--"),
	CannedResponse:        ToPerm("o:---- u:crud a:crud s:cr--"),
	Tag:                   ToPerm("o:---- u:---- a:crud s:cr--"),
	WhitelistIp:           ToPerm("o:---- u:---- a:crud s:cr--"),
	WhitelistUser:         ToPerm("o:---- u:---- a:crud s:cr--"),
	WhitelistDomain:       ToPerm("o:---- u:---- a:crud s:cr--"),
	Widget:                ToPerm("o:---- u:---- a:cru- s:cr--"),
	Subscription:          ToPerm("o:---- u:---- a:cru- s:crud"),
	Invoice:               ToPerm("o:---- u:-r-- a:-r-- s:cru-"),
	PaymentMethod:         ToPerm("o:---- u:---- a:crud s:crud"),
	Bill:                  ToPerm("o:---- u:---- a:-r-- s:cru-"),
	PaymentLog:            ToPerm("o:---- u:---- a:-r-- s:-r--"),
	PaymentComment:        ToPerm("o:---- u:---- a:---- s:crud"),
	User:                  ToPerm("o:---- u:crud a:crud s:cru-"),
	Automation:            ToPerm("o:-r-- u:---- a:crud s:cr--"),
	Ping:                  ToPerm("o:---- u:crud a:crud s:----"),
	Attribute:             ToPerm("o:---- u:---- a:crud s:-r--"),
	AgentNotification:     ToPerm("o:---- u:crud a:---- s:-r--"),
	ConversationExport:    ToPerm("o:---- u:---- a:c--- s:----"),
	ConversationReport:    ToPerm("o:---- u:---- a:-r-- s:-r--"),
	Content:               ToPerm("o:-ru- u:---- a:crud s:crud"),
	Pipeline:              ToPerm("o:---- u:---- a:crud s:-r--"),
	Currency:              ToPerm("o:---- u:---- a:crud s:-r--"),
	ServiceLevelAgreement: ToPerm("o:---- u:---- a:crud s:-r--"),
	MessageTemplate:       ToPerm("o:---- u:crud a:crud s:-r--"),
	PromotionCode:         ToPerm("o:---- u:---- a:---- s:crud"),
	Referral:              ToPerm("o:---- u:crud a:---- s:crud"),
}

// MakeBase returns copy of Base permission
func MakeBase() common.Permission { return Base }
