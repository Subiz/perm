package perm

import (
	scope "bitbucket.org/subiz/auth/scope"
	"context"
	"git.subiz.net/errors"
	"git.subiz.net/header/auth"
	"git.subiz.net/header/lang"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/naming"
	"log"
	"reflect"
	"strings"
	"time"
)

type key int

const (
	credential key = 0
)

// Perm manage user permission and provide some method for quick checking permission
type Perm struct {
	c auth.PermClient
}

func (me Perm) Update(accid, userid string, method auth.Method) {
	ctx := context.Background()
	me.c.Update(ctx, &auth.UpdatePermRequest{AccountId: accid, UserId: userid, Method: &method})
}

func (me Perm) Read(accid, userid string) auth.Method {
	ctx := context.Background()
	resp, err := me.c.Read(ctx, &auth.ReadPermRequest{AccountId: accid, UserId: userid})
	if err != nil {
		panic(errors.New(500, lang.T_internal_error))
	}
	return *resp
}

func (me Perm) UpdateState(accid, userid string, isactive bool) {
	ctx := context.Background()
	me.c.UpdateState(ctx, &auth.UpdateStateRequest{AccountId: accid, UserId: userid, IsActive: isactive})
}

func (me Perm) ListUsersByMethod(accid string, method auth.Method, startid string, limit int) []string {
	ctx := context.Background()
	resp, err := me.c.ListUsersByMethod(ctx, &auth.ListUsersRequest{
		AccountId: accid,
		Method:    &method,
		StartId:   startid,
		Limit:     int32(limit),
	})
	if err != nil {
		panic(errors.New(500, lang.T_internal_error))
	}
	return resp.GetIds()
}

func (me Perm) Check(cred *auth.Credential, accid, issuer string, methods ...auth.Method) {
	if cred.GetAccountId() == "" {
		panic(errors.New(400, lang.T_invalid_credential))
	}

	if cred == nil {
		panic(errors.New(400, lang.T_invalid_credential))
	}

	if len(methods) == 0 {
		panic(errors.New(400, lang.T_internal_error, "method should not be empty"))
	}

	if accid != "" && cred.GetAccountId() != accid {
		panic(errors.New(400, lang.T_wrong_account_in_credential))
	}

	if issuer != "" && issuer != cred.GetIssuer() {
		panic(errors.New(400, lang.T_wrong_user_in_credential))
	}

	ctx := context.Background()
	usermethod, err := me.c.Read(ctx, &auth.ReadPermRequest{AccountId: cred.GetAccountId(), UserId: cred.GetIssuer()})
	if err != nil {
		panic(errors.New(500, lang.T_internal_error))
	}
	clientmethod := cred.GetMethod()
	realmethod := scope.IntersectMethod(*clientmethod, *usermethod)

	for _, method := range methods {
		if scope.RequireMethod(realmethod, method) {
			return
		}
	}
	panic(errors.New(400, lang.T_access_deny))
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
	cred := getCredential(ctx)
	if cred == nil {
		if !scope.IsNilMethod(method) {
			return nil
		}
		return errors.New(400, lang.T_credential_not_set)
	}
	if accid != "" && cred.GetAccountId() != accid {
		return errors.New(400, lang.T_wrong_account_in_credential)
	}

	accmethod := filterAccMethod(method)
	ctx2 := context.Background()
	usermethod, err := me.c.Read(ctx2, &auth.ReadPermRequest{AccountId: cred.GetAccountId(), UserId: cred.GetIssuer()})
	if err != nil {
		return err
	}

	clientmethod := cred.GetMethod()
	realmethod := scope.IntersectMethod(*clientmethod, *usermethod)

	if !scope.IsNilMethod(accmethod) && scope.RequireMethod(realmethod, accmethod) {
		return nil
	}

	err = me.checkSpecialMethod(*clientmethod, method)
	if err != nil {
		return err
	}

	if userid != cred.GetIssuer() {
		return errors.New(400, lang.T_wrong_user_in_credential)
	}
	agentmethod := filterAgentMethod(method)
	if !scope.RequireMethod(realmethod, agentmethod) {
		return errors.New(400, lang.T_access_deny)
	}
	return nil
}

// checkSpecialMethod returns error if client method don't have enought
// rquired method
func (me Perm) checkSpecialMethod(clientmethod, requiredmethod auth.Method) error {
	if requiredmethod.GetResetPassword() && !clientmethod.GetResetPassword() {
		return errors.New(400, lang.T_access_deny)
	}
	return nil
}

func (me Perm) AllowByUser(accid, userid string, method auth.Method) error {
	ctx := context.Background()
	usermethod, err := me.c.Read(ctx, &auth.ReadPermRequest{AccountId: accid, UserId: userid})
	if err != nil {
		return err
	}
	accmethod := filterAccMethod(method)
	if scope.RequireMethod(*usermethod, accmethod) {
		return nil
	}
	return errors.New(400, lang.T_access_deny)
}

// GetCredential extract credential from context
func getCredential(ctx context.Context) *auth.Credential {
	cred, ok := ctx.Value(credential).(*auth.Credential)
	if !ok {
		return &auth.Credential{}
	}
	return cred
}

// AllowOnlyAcc allow only account method to pass
func (me Perm) AllowOnlyAcc(ctx context.Context, accid string, method auth.Method) error {
	cred := getCredential(ctx)
	if accid != "" && cred.GetAccountId() != accid {
		return errors.New(400, lang.T_wrong_account_in_credential)
	}
	clientmethod := cred.GetMethod()
	err := me.checkSpecialMethod(*clientmethod, method)
	if err != nil {
		return err
	}

	ctx2 := context.Background()
	usermethod, err := me.c.Read(ctx2, &auth.ReadPermRequest{AccountId: cred.GetAccountId(), UserId: cred.GetIssuer()})
	if err != nil {
		return err
	}
	realmethod := scope.IntersectMethod(*clientmethod, *usermethod)

	accmethod := filterAccMethod(method)
	if scope.RequireMethod(realmethod, accmethod) {
		return nil
	}
	return errors.New(400, lang.T_access_deny)
}

// filterAccMethod return only acc method
func filterAccMethod(method auth.Method) auth.Method {
	accmethod := auth.Method{
		UpdateAgents:           true,
		ReadAgents:             true,
		ReadAccount:            true,
		UpdateAgentsPermission: true,
		UpdateAgentsState:      true,
	}
	return scope.IntersectMethod(method, accmethod)
}

func filterAgentMethod(method auth.Method) auth.Method {
	return scope.SubstractMethod(method, filterAccMethod(method))
}

// Config config perm
func (me *Perm) Config(permAddress string) {
	permConn, err := dialGrpc(permAddress)
	if err != nil {
		log.Println("unable to connect to :"+permAddress+" service", err)
		return
	}

	me.c = auth.NewPermClient(permConn)
}

func dialGrpc(service string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	// Enabling WithBlock tells the client to not give up trying to find a server
	opts = append(opts, grpc.WithBlock())
	// However, we're still setting a timeout so that if the server takes too long, we still give up
	opts = append(opts, grpc.WithTimeout(10*time.Second))
	res, err := naming.NewDNSResolverWithFreq(1 * time.Second)
	if err != nil {
		return nil, err
	}
	opts = append(opts, grpc.WithBalancer(grpc.RoundRobin(res)))
	return grpc.Dial(service, opts...)
}

func removeDuplicates(elements string) string {
	encountered := map[rune]bool{}
	result := ""
	for _, v := range elements {
		if encountered[v] == true {
		} else {
			encountered[v] = true
			result += string(v)
		}
	}
	return result
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

func ToPerm(p string) int32 {
	rawperms := strings.Split(strings.TrimSpace(p), " ")
	um, gm, om := "", "", ""
	for _, perm := range rawperms {
		perm = strings.TrimSpace(strings.ToLower(perm))
		if len(perm) < 2 {
			continue
		}

		if perm[0] == 'u' {
			um = removeDuplicates(um + perm[1:])
		} else if perm[0] == 'g' {
			gm = removeDuplicates(gm + perm[1:])
		} else if perm[0] == 'o' {
			om = removeDuplicates(om + perm[1:])
		} else {
			continue
		}
	}
	return strPermToInt(um) | strPermToInt(gm)<<4 | strPermToInt(om)<<8
}

func equalPermission(a, b *auth.Permission) bool {
	return proto.Equal(a, b)
}

func intersectPermission(a, b *auth.Permission) *auth.Permission {
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
