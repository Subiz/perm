package perm

import (
	"git.subiz.net/goutils/grpc"
	"git.subiz.net/header/auth"
	cpb "git.subiz.net/header/common"
	"testing"
)

func TestCheckPerm(t *testing.T) {
	tcs := []struct {
		desc    string
		perm    *auth.Permission
		ismine  bool
		isgroup bool
		require *auth.RequirePerm
		expect  bool
	}{{
		"1",
		nil,
		true,
		true,
		nil,
		true,
	}, {
		"2",
		&auth.Permission{},
		true,
		true,
		&auth.RequirePerm{},
		true,
	}, {
		"my resource",
		&auth.Permission{Widget: ToPerm("u:c")},
		true,
		true,
		&auth.RequirePerm{Widget: "u:c"},
		true,
	}, {
		"my resource deny",
		&auth.Permission{Widget: ToPerm("u:u")},
		true,
		false,
		&auth.RequirePerm{Widget: "u:r"},
		false,
	}, {
		"other resource",
		&auth.Permission{Widget: ToPerm("s:u")},
		false,
		false,
		&auth.RequirePerm{Widget: "s:u"},
		true,
	}, {
		"other resource deny 1",
		&auth.Permission{Widget: ToPerm("u:u s:u")},
		false,
		false,
		&auth.RequirePerm{Widget: "u:u"},
		false,
	}, {
		"other resource deny 2",
		&auth.Permission{Widget: ToPerm("s:r")},
		false,
		false,
		&auth.RequirePerm{Widget: "o:u"},
		false,
	}, {
		"group resource",
		&auth.Permission{Widget: ToPerm("a:r")},
		false,
		true,
		&auth.RequirePerm{Widget: "a:r"},
		true,
	}, {
		"group resource deny",
		&auth.Permission{Widget: ToPerm("a:u")},
		false,
		true,
		&auth.RequirePerm{Widget: "a:r"},
		false,
	}, {
		"group resource deny",
		&auth.Permission{Widget: ToPerm("ucrud  gcrud ocrud")},
		false,
		true,
		&auth.RequirePerm{Widget: "u:cu"},
		false,
	}}

	for _, tc := range tcs {
		ctx := grpc.ToGrpcCtx(&cpb.Context{Credential: &auth.Credential{Perm: tc.perm}})
		err := Check(ctx, tc.ismine, tc.isgroup, tc.require)
		if (err == nil) != tc.expect {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, err)
		}
	}
}

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
	p := intersectPermission(&auth.Permission{
		Widget: ToPerm("s:rud a:c u:r"),
	}, &auth.Permission{
		Widget: ToPerm("s:cru a:c u:u"),
	})
	if equalPermission(p, &auth.Permission{
		Widget: ToPerm("u:ru a:c"),
	}) {
		t.Error("err")
	}

	p = intersectPermission(nil, &auth.Permission{
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
		"CheckReadAutomation",
		&auth.Credential{
			AccountId: "ac1",
			Issuer:    "ag1",
			Perm:      &auth.Permission{Automation: ToPerm("u:r")},
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
		Perm:      &auth.Permission{Account: ToPerm("u:c")},
	}, "ac123", "ag1", "ag2")
	if err != nil {
		t.Error(err)
	}

	err = CheckReadBasicScopePermission(&auth.Credential{
		AccountId: "ac123",
		Issuer:    "ag2",
		Perm:      &auth.Permission{BasicScopePermission: ToPerm("u:r s:r a:r")},
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
