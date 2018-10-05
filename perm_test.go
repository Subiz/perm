package perm

import (
	"git.subiz.net/header/auth"
	"github.com/golang/protobuf/proto"
	"testing"
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
	p := IntersectPermission(&auth.Permission{
		Widget: ToPerm("s:rud a:c u:r"),
	}, &auth.Permission{
		Widget: ToPerm("s:cru a:c u:u"),
	})
	if equalPermission(p, &auth.Permission{
		Widget: ToPerm("u:ru a:c"),
	}) {
		t.Error("err")
	}

	p = IntersectPermission(nil, &auth.Permission{
		Widget: ToPerm("s:cru a:c u:u"),
	})
	if equalPermission(p, &auth.Permission{
		Widget: ToPerm("u:ru a:c"),
	}) {
		t.Error("err")
	}
}

func TestFilterPerm(t *testing.T) {
	tcs := []struct {
		desc   string
		r      string
		perm   *auth.Permission
		expect *auth.Permission
	}{{
		"1",
		"u",
		&auth.Permission{Widget: ToPerm("s:crud u:crud")},
		&auth.Permission{Widget: ToPerm("u:crud")},
	}, {
		"2",
		"s",
		&auth.Permission{Widget: ToPerm("s:cud u:crud")},
		&auth.Permission{Widget: ToPerm("s:cud")},
	}, {
		"3",
		"a",
		&auth.Permission{Widget: ToPerm("s:cud u:crud")},
		&auth.Permission{Widget: ToPerm("")},
	}, {
		"4",
		"o",
		nil,
		&auth.Permission{},
	}, {
		"5",
		"x",
		&auth.Permission{Widget: ToPerm("s:cud u:crud")},
		&auth.Permission{},
	}}

	for _, tc := range tcs {
		out := filterPerm(tc.r, tc.perm)
		if !equalPermission(out, tc.expect) {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, out)
		}
	}
}

func TestCheck(t *testing.T) {
	tcs := []struct {
		desc     string
		funcname string
		cred     *auth.Credential
		accid    string
		agids    []string
		pass     bool
	}{{
		"nil check",
		"CheckReadAutomation",
		nil,
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"user accept",
		"CheckReadUser",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &auth.Permission{User: ToPerm("u:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"account accept",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &auth.Permission{Automation: ToPerm("a:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"subiz accept",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "acx",
			Issuer:    "agx",
			Perm:      &auth.Permission{Automation: ToPerm("s:r")},
		},
		"ac1",
		[]string{"ag1"},
		true,
	}, {
		"user reject",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &auth.Permission{Automation: ToPerm("u:w")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"account reject",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &auth.Permission{Automation: ToPerm("a:w")},
		},
		"ac1",
		[]string{"ag2"},
		false,
	}, {
		"subiz reject",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "acx",
			Issuer:    "agx",
			Perm:      &auth.Permission{Automation: ToPerm("s:w")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"user reject 2",
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &auth.Permission{Automation: ToPerm("u:r")},
		},
		"ac1",
		[]string{"ag1"},
		false,
	}, {
		"user reject by base",
		"CheckDeleteAgent",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &auth.Permission{Agent: ToPerm("u:d")},
		},
		"ac1",
		[]string{"ag2"},
		false,
	}, {
		"empty account id",
		"CheckDeleteAttribute",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag2",
			Perm:      &auth.Permission{Agent: ToPerm("u:d")},
		},
		"",
		[]string{"ag1"},
		false,
	}}

	for _, tc := range tcs {
		err := check(tc.funcname, tc.cred, tc.accid, tc.agids)
		if err == nil != tc.pass {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.pass, err)
		}
	}
}

func TestPerm(t *testing.T) {
	var err error
	err = CheckCreateAccount(&auth.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &auth.Permission{Account: ToPerm("s:c")},
	}, "x", "ag1", "ag2")
	if err != nil {
		t.Error(err)
	}

	err = CheckReadPermission(&auth.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &auth.Permission{Permission: ToPerm("u:r s:r a:r")},
	}, "ac12", "ag5", "ag6")
	if err != nil {
		t.Error(err)
	}

	err = CheckCreateAccount(nil, "ac123", "ag1", "ag2")
	if err == nil {
		t.Error("should be err")
	}

	err = CheckCreateAccount(&auth.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &auth.Permission{Widget: ToPerm("u:crud")},
	}, "ac123", "ag2", "ag2")
	if err == nil {
		t.Error("expect error")
	}
}

func TestMerge(t *testing.T) {
	tcs := []struct {
		desc         string
		a, b, expect *auth.Permission
	}{{
		"0",
		nil,
		nil,
		&auth.Permission{},
	}, {
		"1",
		&auth.Permission{
			Account: 0xF0,
		},
		&auth.Permission{
			Account: 0x0F,
		},
		&auth.Permission{
			Account: 0xFF,
		},
	}, {
		"1",
		&auth.Permission{
			Account: 0xF0,
		},
		&auth.Permission{
			Agent: 0x0F,
		},
		&auth.Permission{
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

func equalPermission(a, b *auth.Permission) bool {
	return proto.Equal(a, b)
}
