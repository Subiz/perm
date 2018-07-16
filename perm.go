package perm

import (
	"context"
	"git.subiz.net/header/auth"
	"bitbucket.org/subiz/gocommon"
	scope "bitbucket.org/subiz/auth/scope"
	"bitbucket.org/subiz/perm/db"
	"git.subiz.net/header/lang"
)

// Perm manage user permission and provide some method for quick checking permission
type Perm struct {
	db DB
}

type DB interface {
	Update(accid, userid string, method auth.Method)
	UpdateState(accid, userid string, isactive bool)
	Read(accid, userid string) auth.Method
	ListUsersByMethod(accid string, method auth.Method, startid string, limit int) []string
}

func (me Perm) Update(accid, userid string, method auth.Method) {
	me.db.Update(accid, userid, method)
}

func (me Perm) Read(accid, userid string) auth.Method {
	return me.db.Read(accid, userid)
}

func (me Perm) UpdateState(accid, userid string, isactive bool) {
	me.db.UpdateState(accid, userid, isactive)
}

func (me Perm) ListUsersByMethod(accid string, method auth.Method, startid string, limit int) []string {
	return me.db.ListUsersByMethod(accid, method, startid, limit)
}

func (me Perm) Check(cred *auth.Credential, accid, issuer string, methods ...auth.Method) {
	if cred.GetAccountId() == "" {
		panic(common.New400(lang.T_invalid_credential))
	}

	if cred == nil {
		panic(common.New400(lang.T_invalid_credential))
	}

	if len(methods) == 0 {
		panic(common.New500(lang.T_internal_error, "method should not be empty"))
	}

	if accid != "" && cred.GetAccountId() != accid {
		panic(common.New400(lang.T_wrong_account_in_credential))
	}

	if issuer != "" && issuer != cred.GetIssuer() {
		panic(common.New400(lang.T_wrong_user_in_credential))
	}

	usermethod := me.db.Read(cred.GetAccountId(), cred.GetIssuer())
	clientmethod := cred.GetMethod()
	realmethod := scope.IntersectMethod(*clientmethod, usermethod)

	for _, method := range methods {
		if scope.RequireMethod(realmethod, method) {
			return
		}
	}
	panic(common.New400(lang.T_access_deny))
}

// Allow pass if credential have right to do accmethod OR usermethod on userid
// It MUST panic if the credential doesn't have enough permission
// Specifically, it ONLY return success either when *acc check* or when *agent check*
// are passed.
//   *acc check* is the process of making sure that the invoker has enough
//     *acc method* (*acc methods* are methods act on all agents, ex: UpdateAgents,
//     ResetAgentsPassword).
//   *agent check* is the process of making sure that the invoker has enough *agent
//     method* (*agent method* are methods act on one agent, ex: UpdateAgent,
//     ResetAgentPassword)
//
// let:
// user methods are methods granted to user by the owner (stored in our database)
// client methods are methods granted to app by an agent. (stored in access token)
// real methods are the intersection of user methods and real methods
//
// *acc check* passed only if real methods have every methods in acc method
// *agent check* passed when credential is credential of agent, and real methods have
// every method in agentmethod
// The reason we need *real methods* is that we cannot simply rely on client
// methods to determind whether the client have enought right to execute an action,
// since user may grant client any methods its currently don't have, such as:
// DeleteAccount. Or may be, user were having the permission when granted to client
// and now being revoke by owner. Also, we can't just rely on user methods neither,
// since user may disallow client to do some action. Intersecting client method and
// user method remove all illegal (or stale) cases above.
//
// Updated: there are some special methods, like CreateAccount, DeleteAccount, ...
// There is none users have those, even account owners. Only some internal clients
// are granted those methods
func (me Perm) Allow(ctx context.Context, accid, userid string, method auth.Method) error {
	cred := common.GetCredential(ctx)
	if cred == nil {
		if !scope.IsNilMethod(method) {
			return nil
		}
		return common.New400(lang.T_credential_not_set)
	}
	if accid != "" && cred.GetAccountId() != accid {
		return common.New400(lang.T_wrong_account_in_credential)
	}

	accmethod := filterAccMethod(method)
	usermethod := me.db.Read(cred.GetAccountId(), cred.GetIssuer())
	clientmethod := cred.GetMethod()
	realmethod := scope.IntersectMethod(*clientmethod, usermethod)

	if !scope.IsNilMethod(accmethod) && scope.RequireMethod(realmethod, accmethod) {
		return nil
	}

	err := me.checkSpecialMethod(*clientmethod, method)
	if err != nil {
		return err
	}

	if userid != cred.GetIssuer() {
		return common.New400(lang.T_wrong_user_in_credential)
	}
	agentmethod := filterAgentMethod(method)
	if !scope.RequireMethod(realmethod, agentmethod) {
		common.New400(lang.T_access_deny)
	}
	return nil
}

// checkSpecialMethod returns error if client method don't have enought
// rquired method
func (me Perm) checkSpecialMethod(clientmethod, requiredmethod auth.Method) error {
	if requiredmethod.GetResetPassword() && !clientmethod.GetResetPassword() {
		return common.New400(lang.T_access_deny)
	}
	return nil
}

func (me Perm) AllowByUser(accid, userid string, method auth.Method) error {
	usermethod := me.db.Read(accid, userid)
	accmethod := filterAccMethod(method)
	if scope.RequireMethod(usermethod, accmethod) {
		return nil
	}
	return common.New400(lang.T_access_deny)
}

// AllowOnlyAcc allow only account method to pass
func (me Perm) AllowOnlyAcc(ctx context.Context, accid string, method auth.Method) error {
	cred := common.GetCredential(ctx)
	if accid != "" && cred.GetAccountId() != accid {
		return common.New400(lang.T_wrong_account_in_credential)
	}
	clientmethod := cred.GetMethod()
	err := me.checkSpecialMethod(*clientmethod, method)
	if err != nil {
		return err
	}

	usermethod := me.db.Read(cred.GetAccountId(), cred.GetIssuer())
	realmethod := scope.IntersectMethod(*clientmethod, usermethod)

	accmethod := filterAccMethod(method)
	if scope.RequireMethod(realmethod, accmethod) {
		return nil
	}
	return common.New400(lang.T_access_deny)
}

// True return pointer to true
func True() *bool {
	return common.AmpB(true)
}

// False return pointer to false
func False() *bool {
	return common.AmpB(false)
}

// filterAccMethod return only acc method
func filterAccMethod(method auth.Method) auth.Method {
	accmethod := auth.Method{
		UpdateAgents: true,
		ReadAgents: true,
		ReadAccount: true,
		UpdateAgentsPermission: true,
		UpdateAgentsState: true,
	}
	return scope.IntersectMethod(method, accmethod)
}

func filterAgentMethod(method auth.Method) auth.Method {
	return scope.SubstractMethod(method, filterAccMethod(method))
}

// Config config perm
func (me *Perm) Config(cassseeds []string, prefix string, replicafactor int) {
	db := &db.PermDB{}
	db.Config(cassseeds, prefix, replicafactor)
	me.db = db
}
