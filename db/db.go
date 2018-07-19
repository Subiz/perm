package db

import (
	scope "bitbucket.org/subiz/auth/scope"
	"fmt"
	"git.subiz.net/errors"
	pb "git.subiz.net/header/auth"
	"git.subiz.net/header/lang"
	"github.com/cenkalti/backoff"
	"github.com/gocql/gocql"
	"github.com/golang/protobuf/proto"
	"time"
)

const (
	keyspace         = "perms"
	tablePermissions = "perms"
)

// PermDB manage permissions
type PermDB struct {
	seeds     []string
	session   *gocql.Session
	keyspace  string
	repfactor int
}

// NewPermDB create new PermDB object
func (me *PermDB) Config(seeds []string, keyspaceprefix string, repfactor int) {
	me.seeds = seeds
	me.repfactor = repfactor
	me.keyspace = keyspaceprefix + keyspace
	cluster := gocql.NewCluster(me.seeds...)
	cluster.Timeout = 10 * time.Second
	me.createKeyspace(cluster)
	me.createTables(cluster)
}

func (me *PermDB) createTables(cluster *gocql.ClusterConfig) {
	cluster.Keyspace = me.keyspace
	var err error
	me.session, err = cluster.CreateSession()
	if err != nil {
		panic(err)
	}
	err = me.session.Query(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		user_id ASCII,
		account_id ASCII,
		is_inactive BOOLEAN,
		method BLOB,
		PRIMARY KEY (account_id, user_id)
	) WITH CLUSTERING ORDER BY (user_id ASC)`, tablePermissions)).Exec()
	if err != nil {
		panic(err)
	}
}

func (me *PermDB) createKeyspace(cluster *gocql.ClusterConfig) {
	cluster.Keyspace = "system"
	ticker := backoff.NewTicker(backoff.NewExponentialBackOff())
	var err error
	var defsession *gocql.Session
	for range ticker.C {
		defsession, err = cluster.CreateSession()
		if err == nil {
			ticker.Stop()
			break
		}
		println(err, "will retry...")
	}
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_database_error, "failed to connect to cluster: %v", me.seeds))
	}

	defer defsession.Close()
	err = defsession.Query(fmt.Sprintf(
		`CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {
			'class': 'SimpleStrategy',
			'replication_factor': %d
		}`, me.keyspace, me.repfactor)).Exec()
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_database_error, "failed to create keyspace %s", me.keyspace))
	}
}

// Update update or create method for user
func (me PermDB) Update(accid, userid string, method pb.Method) {
	err := me.session.Query(fmt.Sprintf(`UPDATE %s SET method=? WHERE account_id=? AND user_id=?`, tablePermissions), protify(&method), accid, userid).Exec()
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_database_error, "unable to update user %s in account %s", userid, accid))
	}
}

// UpdateState update state for user
func (me PermDB) UpdateState(accid, userid string, isactive bool) {
	err := me.session.Query(fmt.Sprintf(`UPDATE %s SET is_inactive=? WHERE account_id=? AND user_id=?`, tablePermissions), !isactive, accid, userid).Exec()
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_database_error, "unable to update state of user %s in account %s", userid, accid))
	}
}

// Read read method for user, return default pb.Method if not found
func (me PermDB) Read(accid, userid string) pb.Method {
	var met []byte
	err := me.session.Query(fmt.Sprintf(`SELECT method FROM %s WHERE account_id=? AND user_id=?`, tablePermissions), accid, userid).Scan(&met)
	if err != nil {
		if err.Error() == gocql.ErrNotFound.Error() {
			return pb.Method{}
		}
		panic(errors.Wrap(err, 500, lang.T_database_error, "unable to select method from account %s and user %s", accid, userid))
	}
	method := pb.Method{}
	parseProto(met, &method)
	return method
}

// ListUsersByMethod list active users that statisfy method, limit should less than 3000
func (me PermDB) ListUsersByMethod(accid string, method pb.Method, startid string, limit int) []string {
	if limit < 0 || limit > 3000 {
		limit = 3000
	}
	iter := me.session.Query(fmt.Sprintf(`SELECT user_id, is_inactive, method FROM %s WHERE account_id=? AND user_id>?`, tablePermissions), accid, startid).PageSize(2000).Iter()
	ids := make([]string, 0)
	var id string
	var met []byte
	var isinactive bool
	for iter.Scan(&id, &isinactive, &met) {
		usermethod := &pb.Method{}
		parseProto(met, usermethod)
		if isinactive {
			continue
		}
		if !scope.RequireMethod(*usermethod, method) {
			continue
		}
		ids = append(ids, id)
		if len(ids) == limit {
			break
		}
	}
	if err := iter.Close(); err != nil {
		panic(errors.Wrap(err, 500, lang.T_database_error, "failed to close iter for account %s", accid))
	}

	return ids
}

// ParseProto convert protobuf byte[] to struct
func parseProto(p []byte, out proto.Message) {
	err := proto.Unmarshal(p, out)
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_invalid_protobuf, "unable to unmashal proto from '%v'", p))
	}
}

func protify(p proto.Message) []byte {
	bytes, err := proto.Marshal(p)
	if err != nil {
		panic(errors.Wrap(err, 500, lang.T_invalid_protobuf, "unable to protify struct %v", p))
	}
	return bytes
}
