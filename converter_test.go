package perm

import (
	"git.subiz.net/header/auth"
	"github.com/golang/protobuf/proto"
	"testing"
)

func TestConvertMethodToPerm(t *testing.T) {
	tcs := []struct {
		desc   string
		m      *auth.Method
		expect *auth.Permission
	}{{
		"1",
		nil,
		&auth.Permission{},
	}, {
		"1",
		&auth.Method{},
		&auth.Permission{},
	}, {
		"2",
		&auth.Method{
			ReadSegmentation:   true,
			UpdateSegmentation: true,
			DeleteAgentGroup:   true,
		},
		&auth.Permission{
			Segmentation: ToPerm("a:ru"),
			AgentGroup:   ToPerm("a:d"),
		},
	}}

	for _, tc := range tcs {
		out := MethodToPerm(tc.m)
		if !proto.Equal(out, tc.expect) {
			t.Errorf("[%s] expect %v, got %v", tc.desc, tc.expect, out)
		}
	}
}
