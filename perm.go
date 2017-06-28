package perm

import (
	"golang.org/x/net/context"
	"bitbucket.org/subiz/servicespec/proto/auth"
	"bitbucket.org/subiz/gocommon"
	scope "bitbucket.org/subiz/scopemgr"
)

// Perm manage user permission and provide some method for quick checking permission
type Perm struct {
	db DB
}

type DB interface {
	Update(accid, userid string, method *auth.Method)
	UpdateState(accid, userid string, isactive bool)
	Read(accid, userid string) *auth.Method
	ListUsersByMethod(accid string, method *auth.Method, startid string, limit int) []string
}

func (me *Perm) Update(accid, userid string, method *auth.Method) {
	me.db.Update(accid, userid, method)
}

func (me *Perm) Read(accid, userid string) *auth.Method {
	return me.db.Read(accid, userid)
}

func (me *Perm) UpdateState(accid, userid string, isactive bool) {
	me.db.UpdateState(accid, userid, isactive)
}

func (me *Perm) ListUsersByMethod(accid string, method *auth.Method, startid string, limit int) []string {
	return me.db.ListUsersByMethod(accid, method, startid, limit)
}

// Allow allow context wich credential have right to do accmethod OR usermethod on userid
// It will panic if credential doesn't have enough permission
// Allow only return success when either *acc check* or *agent check* is passed.
// *acc check* is the process to make sure the invoker has enough *acc method* (*acc methods* are
// methods act on all agents, ex: UpdateAgents, ResetAgentsPassword).
// *agent check* is the process to make sure invoker has enough *agent method* (*agent  method*
// are method act on one agent, ex: UpdateAgent, ResetAgentPassword)
//
// There are 3 type of method: client methods, user methods, real methods:
// user methods are methods granted to user by the owner (storing in our database)
// client methods are methods granted to client (app) by an user. (storing in context)
// real methods is the intersection of user methods and real methods
//
// *acc check* pass if real methods have every method in accmethod
// *agent check* pass when credential is credential of userid, and real methods have every method
// in agentmethod
// The reason we nee *real methods* is that we cannot simply rely on client methods to determind
// whether the client have enought right to execute an action, since user may grant client any
// methods which its don't have (e.g: DeleteAccount). Or may be, it used to have but doesn't have
// it now. We can't just rely on user methods neither, since user may disallow client to do some
// action. Intersecting client method and user method remove all illegal above illegal (or stale)
// methods.
//
// Updated: there are some special methods, like CreateAccount, DeleteAccount, ... No users have
// those, even account owners. Only some internal clients are granted those methods
func (me *Perm) Allow(ctx context.Context, accid, userid string, method *auth.Method) {
	cred := common.ExtractCredFromCtx(ctx)
	if accid != "" && cred.AccountId != accid {
		panic(common.NewForbiddenErr("wrong account"))
	}
	me.checkSpecialMethod(cred.Method, method)
	clientmethod := cred.Method
	usermethod := me.db.Read(cred.AccountId, cred.UserId)
	realmethod := scope.IntersectMethod(clientmethod, usermethod)

	accmethod := filterAccMethod(method)
	if scope.RequireMethod(realmethod, accmethod) {
		return
	}

	if userid != cred.UserId {
		panic(common.NewForbiddenErr())
	}
	agentmethod := filterAgentMethod(method)
	if !scope.RequireMethod(realmethod, agentmethod) {
		panic(common.NewForbiddenErr())
	}
}

func (me *Perm) checkSpecialMethod(clientmethod *auth.Method, requiredmethod *auth.Method) {
	if requiredmethod.CreateAccount && !clientmethod.CreateAccount {
		panic(common.NewForbiddenErr())
	}
	if requiredmethod.DeleteAccount && !clientmethod.DeleteAccount {
		panic(common.NewForbiddenErr())
	}
	if requiredmethod.ResetPassword && !clientmethod.ResetPassword {
		panic(common.NewForbiddenErr())
	}
}

func (me *Perm) AllowByUser(accid, userid string, method *auth.Method) {
	usermethod := me.db.Read(accid, userid)
	accmethod := filterAccMethod(method)
	if scope.RequireMethod(usermethod, accmethod) {
		return
	}
	panic(common.NewForbiddenErr())
}

// AllowOnlyAcc allow only account method to pass
func (me *Perm) AllowOnlyAcc(ctx context.Context, accid string, method *auth.Method) {
	cred := common.ExtractCredFromCtx(ctx)
	if accid != "" && cred.AccountId != accid {
		panic(common.NewForbiddenErr("wrong account"))
	}
	me.checkSpecialMethod(cred.Method, method)
	clientmethod := cred.Method
	usermethod := me.db.Read(cred.AccountId, cred.UserId)
	realmethod := scope.IntersectMethod(clientmethod, usermethod)

	accmethod := filterAccMethod(method)
	if scope.RequireMethod(realmethod, accmethod) {
		return
	}
	panic(common.NewForbiddenErr())
}

func filterAccMethod(method *auth.Method) *auth.Method {
	accmethod := &auth.Method{
		InviteAgents: true,
		UpdateAgents: true,
		ReadAgents: true,
		ReadAccount: true,
		UpdateAgentsPermission: true,
		UpdateAgentsState: true,
		CreateAgentGroups: true,
		DeleteAgentGroups: true,
		ReadAgentGroups: true,
		UpdateAgentGroups: true,
	}
	return scope.IntersectMethod(method, accmethod)
}

func filterAgentMethod(method *auth.Method) *auth.Method {
	return scope.SubstractMethod(method, filterAccMethod(method))
}

func (me *Perm) Config(prefix string, replicafactor int, broker []string) *Perm {
	return &Perm{
	}
}
