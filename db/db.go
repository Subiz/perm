package db

import (
	"github.com/gocql/gocql"
	pb "bitbucket.org/subiz/servicespec/proto/auth"
	"time"
	"fmt"
	scope "bitbucket.org/subiz/scopemgr"
	"bitbucket.org/subiz/gocommon"
)

const (
	keyspacePerm = "perms"
	tablePermissions = "perms"
)

// PermDB manage permissions
type PermDB struct {
	init bool
	seeds []string
	session *gocql.Session
	keyspace string
	repfactor int
}

// NewPermDB create new PermDB object
func NewPermDB(seeds []string, keyspaceprefix string, repfactor int) *PermDB {
	var db = &PermDB{
		init: false,
		seeds: seeds,
		keyspace: keyspaceprefix + keyspacePerm,
		repfactor: repfactor,
	}
	return db
}

func (me *PermDB) createTables(cluster *gocql.ClusterConfig) {
	cluster.Keyspace = me.keyspace
	var err error
	me.session, err = cluster.CreateSession()
	common.Panicf(err, "failed to connect to cluster: %v", me.seeds)
	err = me.session.Query(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		user_id ASCII,
		account_id ASCII,
		is_inactive BOOLEAN,
		method BLOB,
		PRIMARY KEY (account_id, user_id)
	) WITH CLUSTERING ORDER BY (user_id ASC)`, tablePermissions)).Exec()
	common.Panicf(err, "failed to create table %s", tablePermissions)
}

func (me *PermDB) createKeyspace(cluster *gocql.ClusterConfig) {
	cluster.Keyspace = "system"
	var defsession, err = cluster.CreateSession()
	defer defsession.Close()
	common.Panicf(err, "failed to connect to cluster: %v", me.seeds)
	err = defsession.Query(fmt.Sprintf(`
		CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {
			'class': 'SimpleStrategy',
			'replication_factor': %d
		}`, me.keyspace, me.repfactor)).Exec()
	common.Panicf(err, "failed to create keyspace %s", me.keyspace)
}

func (me *PermDB) connect() {
	if me.init {
		return
	}
	me.init = true
	var cluster = gocql.NewCluster(me.seeds...)
	cluster.Timeout = 10 * time.Second
	me.createKeyspace(cluster)
	me.createTables(cluster)
}

// Update update or create method for user
func (me *PermDB) Update(accid, userid string, method *pb.Method) {
	me.connect()
	err := me.session.Query(fmt.Sprintf(`UPDATE %s SET method=? WHERE account_id=? AND user_id=?`,  tablePermissions), common.Protify(method), accid, userid).Exec()
	if err != nil {
		common.Panic(common.NewInternalErr("%v, unable to update user %s in account %s", err, userid, accid))
	}
}

// UpdateState update state for user
func (me *PermDB) UpdateState(accid, userid string, isactive bool) {
	me.connect()
	err := me.session.Query(fmt.Sprintf(`UPDATE %s SET is_inactive=? WHERE account_id=? AND user_id=?`, tablePermissions), !isactive, accid, userid).Exec()
	if err != nil {
		common.Panic(common.NewInternalErr("%v, unable to update state of user %s in account %s", err, userid, accid))
	}
}

func (me *PermDB) Read(accid, userid string) *pb.Method {
	me.connect()
	var met []byte
	err := me.session.Query(fmt.Sprintf(`SELECT method FROM %s WHERE account_id=? AND user_id=?`, tablePermissions), accid, userid).Scan(&met)
	if err != nil {
		common.Panic(common.NewInternalErr("%v, unable to select method from account %s and user %s", accid, userid))
	}
	method := &pb.Method{}
	common.ParseProto(met, method)
	return method
}

// ListUsersByMethod list active users that statisfy method, limit should less than 3000
func (me *PermDB) ListUsersByMethod(accid string, method *pb.Method, startid string, limit int) []string {
	if limit < 0 || limit > 3000 {
		limit = 3000
	}
	me.connect()
	iter := me.session.Query(fmt.Sprintf(`SELECT user_id, is_inactive, method FROM %s WHERE account_id=? AND user_id>?`, tablePermissions), accid, startid).PageSize(2000).Iter()
	var ids = make([]string, 0)
	var id string
	var met []byte
	var isinactive bool
	for iter.Scan(&id, &isinactive, &met) {
		usermethod := &pb.Method{}
		common.ParseProto(met, usermethod)
		if isinactive { continue }
		if !scope.RequireMethod(usermethod, method) { continue }
		ids = append(ids, id)
		if len(ids) == limit { break }
	}
	var err = iter.Close()
	if err != nil {
		common.Panic(common.NewInternalErr("%v, failed to close iter for account %s", err, accid))
	}
	return ids
}
