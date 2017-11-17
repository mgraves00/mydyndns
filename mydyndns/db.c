/* $Id$ */
/*
 * Copyright (c) 2017 Michael Graves <mgraves@brainfat.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <kcgi.h>
#include <ksql.h>
#include "mydyndns.h"

enum stmt {
	STMT_FIND_USER_BY_NAME,
	STMT_FIND_DOMAIN_BY_NAME,
	STMT_FIND_DOMAIN_BY_USER,
	STMT_INSERT_DOMAIN,
	STMT_UPDATE_DOMAIN,
	STMT__MAX
};

static const char *const stmts[STMT__MAX] = {
	/* FIND USER BY NAME */
	"SELECT name,hash FROM user WHERE name=?",
	/* FIND NAME BY NAME */
	"SELECT * FROM domain WHERE name=?",
	/* FIND NAME BY USER */
	"SELECT address,ttl FROM domain WHERE user=? AND name=?",
	/* INSERT DOMAIN */
	"INSERT INTO domain (address,ttl,user,name) VALUES (?,?,?,?)",
	/* UPDATE DOAMIN */
	"UPDATE domain SET address = ?, ttl = ?, timestamp = datetime('now') WHERE user = ? AND name = ?",
};

void
db_close(struct kreq *r)
{
	ksql_free(r->arg);
	r->arg = NULL;
}

int
db_open(struct kreq *r, const char *file)
{
	struct ksqlcfg	cfg;
	struct ksql	*sql;
	memset(&cfg, 0, sizeof(struct ksqlcfg));
	cfg.flags = KSQL_FOREIGN_KEYS | KSQL_SAFE_EXIT;
	cfg.err = ksqlitemsg;
	cfg.dberr = ksqlitedbmsg;
	if (NULL == (sql = ksql_alloc(&cfg))) {
//		fprintf(stderr, "ksql_alloc\n");
		return(0);
	}
	if (KSQL_OK != ksql_open(sql, file)) {
//		fprintf(stderr, "ksql_alloc\n");
		ksql_free(sql);
		return(0);
	}
	r->arg = sql;
	return(1);
}

int
db_find_domain(struct kreq *r, char *user, char *domain, char **address, char **ttl)
{
	struct ksqlstmt *stmt;
	int rc;
	char *addr;
	char *lttl;

	ksql_stmt_alloc(r->arg, &stmt, stmts[STMT_FIND_DOMAIN_BY_USER], STMT_FIND_DOMAIN_BY_USER);
	ksql_bind_str(stmt, 0, user);
	ksql_bind_str(stmt, 1, domain);
	rc = ksql_stmt_step(stmt);
	if (KSQL_ROW == rc) {
		if ((addr = strdup(ksql_stmt_str(stmt,0))) == NULL) {
			ksql_stmt_free(stmt);
			*address = NULL;
			return(-2);
		}
		*address = addr;
		if ((lttl = strdup(ksql_stmt_str(stmt,1))) == NULL) {
			ksql_stmt_free(stmt);
			free(address);
			*address = NULL;
			*ttl = NULL;
			return(-2);
		}
		*ttl = lttl;
		rc = 1;
	} else if (KSQL_DONE == rc) {
		rc = 0;
	} else {
		rc = -1;
	}
	ksql_stmt_free(stmt);
	return(rc);
}

/*
 * -1: internal error
 *  1: insert/update made
 */
int
db_save_domain(struct kreq *r, const char *user, const char *domain, const char *address, const char *ttl, int x)
{
	struct ksqlstmt *stmt;
	int rc;
	int64_t q;
	const char *errstr;

	q = strtonum(ttl, 0, INTMAX_MAX, &errstr);
	if (errstr != NULL) {
		fprintf(stderr, "errstr %s\n",errstr);
		return(-1);
	}
	ksql_stmt_alloc(r->arg, &stmt, stmts[x], x);
	ksql_bind_str(stmt, 0, address);
	ksql_bind_int(stmt, 1, q);
	ksql_bind_str(stmt, 2, user);
	ksql_bind_str(stmt, 3, domain);
	rc = ksql_stmt_step(stmt);
	if (KSQL_DONE != rc) {
		fprintf(stderr, "ksql_stmt_step != KSQL_DONE\n");
		ksql_stmt_free(stmt);
		return(-1);
	}
	ksql_stmt_free(stmt);
	return(1);
}

/*
 * -x: some internal db error
 *  0: no change
 *  1: update made.  Added or updated
 */
int
db_update_domain(struct kreq *r, char *user, char *domain, char *address, char *ttl)
{
	int rc, stmt = STMT_INSERT_DOMAIN;
	char *laddr;
	char *lttl;

	if ((rc = db_open(r, DB_FILE)) == 0)
		return(-1);	/* open failed */
	rc = db_find_domain(r, user, domain, &laddr, &lttl);
	if (rc < 0) {
		db_close(r);
		return(-1);
	} else if (rc == 1) { /* found a candidate */
		if ((strncasecmp(address,laddr,strlen(address)) == 0) &&
		    (strncasecmp(ttl,lttl,strlen(ttl)) == 0)) {
			// nothing to change
			db_close(r);
			return(0);
		}
		stmt = STMT_UPDATE_DOMAIN;
	}
	rc = db_save_domain(r, user, domain, address, ttl, stmt);
	db_close(r);
	return(rc);
}

/*
 * -1: user not found
 *  0: user & password correct
 *  1: user correct & password not correct
 */
int
db_find_user(struct kreq *r, const char *name, const char *pass)
{
	struct ksqlstmt *stmt;
	char		*user;
	char		*hash;
	int		rc;
	
	if ((rc = db_open(r, DB_FILE)) == 0)
		return(-1);	/* open failed */
	ksql_stmt_alloc(r->arg, &stmt,
		stmts[STMT_FIND_USER_BY_NAME], STMT_FIND_USER_BY_NAME);
	ksql_bind_str(stmt, 0, name);
	if (KSQL_ROW != ksql_stmt_step(stmt)) {
		ksql_stmt_free(stmt);
		db_close(r);
		return(-1);
	}
	if ((user = strdup(ksql_stmt_str(stmt, 0))) == NULL) {
		ksql_stmt_free(stmt);
		db_close(r);
		return(-1);
	}
	if ((hash = strdup(ksql_stmt_str(stmt, 1))) == NULL) {
		ksql_stmt_free(stmt);
		db_close(r);
		return(-1);
	}
	ksql_stmt_free(stmt);
	if (0 == strcmp(hash, pass)) {
		free(user);
		free(hash);
		db_close(r);
		return(0);
	}
	free(user);
	free(hash);
	db_close(r);
	return(1);
}

