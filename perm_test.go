package perm

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/subiz/header/common"
	"github.com/golang/protobuf/proto"
)

func TestCheckToPerm(t *testing.T) {
	tcs := []struct {
		desc   string
		perms  string
		expect int32
	}{
		{"1", "u:r", 0x4},
		{"2", "u:r u:u", 0x6},
		{"3", "u:ru", 0x6},
		{"4", "u:ur", 0x6},
		{"5", "u:ur s:r", 0x406},
		{"6", "u:crud s:crud a:crud", 0xFFF},
	}

	for _, tc := range tcs {
		out := ToPerm(tc.perms)
		if out != tc.expect {
			t.Errorf("[%s] expect %d, got %d", tc.desc, tc.expect, out)
		}
	}
}

func TestIntersectPermission(t *testing.T) {
	p := IntersectPermission(&common.Permission{
		Widget: ToPerm("s:rud a:c u:r"),
	}, &common.Permission{
		Widget: ToPerm("s:cru a:c u:u"),
	})
	if equalPermission(p, &common.Permission{
		Widget: ToPerm("u:ru a:c"),
	}) {
		t.Error("err")
	}

	p = IntersectPermission(nil, &common.Permission{
		Widget: ToPerm("s:cru a:c u:u"),
	})
	if equalPermission(p, &common.Permission{
		Widget: ToPerm("u:ru a:c"),
	}) {
		t.Error("err")
	}
}

func TestCheck(t *testing.T) {
	tcs := []struct {
		desc      string
		checkFunc func(cred *common.Credential, accid string, agids ...string) error
		cred      *common.Credential
		accid     string
		agids     []string
		pass      bool
	}{{
		"nil check",
		CheckReadAutomation,
		nil,
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"user accept",
		CheckReadUser,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &common.Permission{User: ToPerm("u:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"account accept",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &common.Permission{Automation: ToPerm("a:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"subiz accept",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "acx",
			Issuer:    "agx",
			Perm:      &common.Permission{Automation: ToPerm("s:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"user reject",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &common.Permission{Automation: ToPerm("u:w")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"account reject",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &common.Permission{Automation: ToPerm("a:w")},
		},
		"ac1",
		[]string{"ag2"},
		false,
	}, {
		"subiz reject",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "acx",
			Issuer:    "agx",
			Perm:      &common.Permission{Automation: ToPerm("s:w")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"user reject 2",
		CheckReadAutomation,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &common.Permission{Automation: ToPerm("u:r")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"empty account id",
		CheckDeleteAttribute,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &common.Permission{Agent: ToPerm("u:d")},
		},
		"",
		[]string{"ag1"},
		false,
	}, {
		"check super perm same account but has super",
		CheckCreateInvoice,
		&common.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &common.Permission{Invoice: ToPerm("s:c")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}}

	for _, tc := range tcs {
		err := tc.checkFunc(tc.cred, tc.accid, tc.agids...)
		if err == nil != tc.pass {
			t.Errorf("[%s] expect pass: %v, but got err %v", tc.desc, tc.pass, err)
		}
	}
}

func TestPerm(t *testing.T) {
	var err error
	err = CheckCreateAccount(&common.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &common.Permission{Account: ToPerm("s:c")},
	}, "x", "ag1", "ag2")
	if err != nil {
		t.Error(err)
	}

	err = CheckReadPermission(&common.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &common.Permission{Permission: ToPerm("u:r s:r a:r")},
	}, "ac12", "ag5", "ag6")
	if err != nil {
		t.Error(err)
	}

	err = CheckCreateAccount(nil, "ac123", "ag1", "ag2")
	if err == nil {
		t.Error("should be err")
	}

	err = CheckCreateAccount(&common.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &common.Permission{Widget: ToPerm("u:crud")},
	}, "ac123", "ag2", "ag2")
	if err == nil {
		t.Error("expect error")
	}
}

func TestIntersect(t *testing.T) {
	tcs := []struct {
		desc         string
		a, b, expect *common.Permission
	}{{
		"0",
		nil,
		nil,
		&common.Permission{},
	}, {
		"1",
		&common.Permission{
			Account: 0xF0,
		},
		&common.Permission{
			Account: 0x0F,
		},
		&common.Permission{
			Account: 0x00,
		},
	}, {
		"1",
		&common.Permission{
			Account: 0xF0,
		},
		&common.Permission{
			Account: 0xF0,
			Agent:   0x0F,
		},
		&common.Permission{
			Account: 0xF0,
		},
	}}

	for _, tc := range tcs {
		out := Intersect(tc.a, tc.b)
		if !equalPermission(out, tc.expect) {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, out)
		}
	}
}

func TestMerge(t *testing.T) {
	tcs := []struct {
		desc         string
		a, b, expect *common.Permission
	}{{
		"0",
		nil,
		nil,
		&common.Permission{},
	}, {
		"1",
		&common.Permission{
			Account: 0xF0,
		},
		&common.Permission{
			Account: 0x0F,
		},
		&common.Permission{
			Account: 0xFF,
		},
	}, {
		"1",
		&common.Permission{
			Account: 0xF0,
		},
		&common.Permission{
			Agent: 0x0F,
		},
		&common.Permission{
			Account: 0xF0,
			Agent:   0x0F,
		},
	}}

	for _, tc := range tcs {
		out := Merge(tc.a, tc.b)
		if !equalPermission(out, tc.expect) {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, out)
		}
	}
}

func equalPermission(a, b *common.Permission) bool {
	return proto.Equal(a, b)
}

func BenchmarkIntersectPermission(b *testing.B) {
	base := MakeBase()
	for i := 0; i < b.N; i++ {
		IntersectPermission(&base, &base)
	}
}

func TestAgentPerm(t *testing.T) {
	permb, err := hex.DecodeString("10e01f18f61f208e1e306438f01f50ff1f60f01f68f01f70ee1e78f01f8001ff1f8801f01fa001f01fa801f01fb001f01fb801e01fc001e01fc801c01ed001f01fd801c01ee001c01ee801801ef001ff1ff801f01f8002fe1f8802f01f90028f1e9802c01fa002c01ea802f001c8024f")
	if err != nil {
		t.Fatal(err)
	}
	pe := &common.Permission{}
	if err := proto.Unmarshal(permb, pe); err != nil {
		panic(err)
	}

	pe = Merge(pe, GetAgentPerm())
	println(ToPerm("a:--u-"), pe.GetSubscription())
	if proto.Equal(&common.Permission{
		Subscription: ToPerm("a:--u-"),
	}, IntersectPermission(pe, &common.Permission{
		Subscription: ToPerm("a:--u-"),
	})) { // account manage
		pe = Merge(pe, GetAccountManagePerm())
		fmt.Println("got account manage")
	}

	if proto.Equal(pe, IntersectPermission(pe, &common.Permission{
		Permission: ToPerm("a:-ru-"),
	})) { // account setting
		pe = Merge(pe, GetAccountSettingPerm())
		fmt.Println("got account setting")
	}
}
