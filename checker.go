package perm

import (
	"context"

	"bitbucket.org/subiz/auth/scope"
	"git.subiz.net/errors"
	"git.subiz.net/goutils/grpc"
	"git.subiz.net/header/auth"
	"git.subiz.net/header/lang"
)

type rule struct {
	issuer string
	method auth.Method
}

type Checker struct {
	rules []rule
	c     auth.PermClient
}

func (c *Checker) Or(issuer string, method auth.Method) *Checker {
	c.rules = append(c.rules, rule{
		issuer: issuer,
		method: method,
	})
	return c
}

func (me Perm) New() *Checker {
	return &Checker{
		rules: make([]rule, 0),
		c:     me.c,
	}
}

func (c *Checker) Check(ctx context.Context, accid string) {
	cred := getCredential(ctx)
	if cred == nil || cred.GetAccountId() == "" {
		cred = grpc.FromGrpcCtx(ctx).GetCredential()
	}
	c.CheckCred(cred, accid)
}

func (c *Checker) CheckCred(cred *auth.Credential, accid string) {
	if cred == nil {
		panic(errors.New(400, lang.T_invalid_credential))
	}

	if accid != "" && cred.GetAccountId() != accid {
		panic(errors.New(400, lang.T_wrong_account_in_credential))
	}

	issuer := cred.GetIssuer()
	if issuer == "" {
		panic(errors.New(400, lang.T_invalid_credential))
	}

	for _, r := range c.rules {
		if r.issuer != "" && r.issuer != issuer {
			continue
		}

		if r.method == (auth.Method{}) { // skip empty method
			if r.issuer == "" {
				continue
			} else {
				return // passed
			}
		}

		if cred.GetMethod() == nil {
			break
		}

		ctx := context.Background()
		usermethod, err := c.c.Read(ctx, &auth.ReadPermRequest{AccountId: cred.GetAccountId(), UserId: issuer})
		if err != nil {
			panic(errors.New(500, lang.T_internal_error))
		}
		clientmethod := *cred.GetMethod()
		if scope.BothCoverMethod(*usermethod, clientmethod, r.method) {
			return
		}
	}
	panic(errors.New(400, lang.T_access_deny))
}
