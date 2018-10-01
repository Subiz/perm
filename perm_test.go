package perm

import (
	"git.subiz.net/goutils/grpc"
	"testing"
	"git.subiz.net/header/auth"
cpb	"git.subiz.net/header/common"
)

func TestCheckPerm(t *testing.T) {
	tcs := []struct{
		desc string
		perm *auth.Permission
		ismine bool
		isgroup bool
		require *auth.RequirePerm
		expect bool
	}{{
		"1",
		nil,
		true,
		true,
		nil,
		true,
	},{
		"2",
		&auth.Permission{},
		true,
		true,
		&auth.RequirePerm{},
		true,
	},{
		"my resource",
		&auth.Permission{	Widget: ToPerm("u:c")},
		true,
		true,
		&auth.RequirePerm{Widget: "u:c"},
		true,
	},{
		"my resource deny",
		&auth.Permission{Widget: ToPerm("u:u")},
		true,
		false,
		&auth.RequirePerm{Widget: "u:r"},
		false,
	},{
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
	tcs := []struct{
		desc string
		perms string
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
	tcs := []struct{
		desc string
		r string
		perm *auth.Permission
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
