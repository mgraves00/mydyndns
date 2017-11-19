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
#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha1.h>

#include <kcgi.h>
#include <kcgihtml.h>
#include <ksql.h>

#include "mydyndns.h"

#define DEFAULT_REALM "mydyndns"
#define DEFAULT_TTL "86400"

enum	key {
	KEY_MYIP,
	KEY_NAME,
	KEY_TTL,
	KEY_WILDCARD,	// depreciated
	KEY_MX,		// depreciated
	KEY_BACKUPMX,	// depreciated
	KEY_OFFLINE,	// not used
	KEY__MAX
};

static const struct kvalid keys[KEY__MAX] = {
	{ kvalid_stringne, "myip" }, /* KEY_MYIP */
	{ kvalid_stringne, "name" }, /* KEY_NAME */
	{ kvalid_uint, "ttl" }, /* KEY_TTL */
	{ kvalid_stringne, "wildcard" }, /* KEY_WILDCARD */
	{ kvalid_stringne, "mx" }, /* KEY_MX */
	{ kvalid_stringne, "backmx" }, /* KEY_BACKUPMX */
	{ kvalid_stringne, "offline" }, /* KEY_offline */
};

static void
resp_open(struct kreq *req, enum khttp http)
{
	khttp_head(req, kresps[KRESP_STATUS], "%s", khttps[http]);
	khttp_head(req, kresps[KRESP_CONTENT_TYPE], "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_head(req, kresps[KRESP_CACHE_CONTROL], "%s", "no-cache, no-store, must-revalidate");
	khttp_head(req, kresps[KRESP_EXPIRES], "%s", "0");
	khttp_head(req, kresps[KRESP_PRAGMA], "%s", "no-cache");
	khttp_body(req);
}

static void
noauth(struct kreq *req, enum khttp http)
{
	khttp_head(req, kresps[KRESP_STATUS], "%s", khttps[http]);
	khttp_head(req, kresps[KRESP_CONTENT_TYPE], "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_head(req, kresps[KRESP_CACHE_CONTROL], "%s", "no-cache, no-store, must-revalidate");
	khttp_head(req, kresps[KRESP_EXPIRES], "%s", "0");
	khttp_head(req, kresps[KRESP_PRAGMA], "%s", "no-cache");
	khttp_head(req, kresps[KRESP_WWW_AUTHENTICATE], "Basic realm=\"%s\"", DEFAULT_REALM);
	khttp_body(req);
}

static int
save_request(struct kreq *r, char *user, char *name, char *ip, char *ttl)
{
	int rc;
	rc = db_update_domain(r, user, name, ip, ttl);
	return(rc);
}

/*
 *  2: mem error
 *  1: user found, but pass incorrect
 *  0: user found & pass correct
 * -1: =user not found
 */
static int
check_user(struct kreq *r, char *b, char **u)
{
	char *p;
	int rc;
	uint8_t output[SHA1_DIGEST_STRING_LENGTH] = "\0";
	if ((p = strchr(b,':')) == NULL)
		return(2); /* invalid input */
	*p='\0';
	p++;
	if ((*u = strdup(b)) == NULL)
		return(2); /* cannot copy user */
	SHA1Data(p,strlen(p),output);
	rc = db_find_user(r, *u, output);
	return rc;	
}

int
main(void)
{
	struct kreq	 r;
	enum kcgi_err	 er;
	struct kpair	*p;
	char *myip = NULL;
	char *name = NULL;
	char *user = NULL;
	char *ttl = NULL;
	char buf[1024] = "\0";
	int64_t x;
	int rc;
	size_t i;

	/*
	if (0 == kutil_openlog(NULL)) {
		fprintf(stderr, "kutil_openlog");
		khttp_free(&r);
		return(EXIT_FAILURE);
	}
	*/

	er = khttp_parse(&r, keys, KEY__MAX, NULL, 0, 0);
	if (KCGI_OK != er) {
		fprintf(stderr, "Terminate: parse error: %d\n", er);
		khttp_free(&r);
		return(EXIT_FAILURE);
	}

	if (KMETHOD_GET != r.method && KMETHOD_POST != r.method) {
		resp_open(&r, KHTTP_405);
		khttp_free(&r);
		free(user);
		return(EXIT_SUCCESS);
	}

	if (r.reqmap[KREQU_AUTHORIZATION] == NULL) {
		noauth(&r,KHTTP_401);
		khttp_puts(&r, "badauth");
		khttp_free(&r);
		return(EXIT_SUCCESS);
	}
	if ((rc = base64_pton(r.rawauth.d.basic.response, buf, sizeof(buf))) == -1) {
		noauth(&r, KHTTP_401);
		khttp_puts(&r, "badauth");
		khttp_free(&r);
		return(EXIT_SUCCESS);
	}
	if (check_user(&r, buf, &user) != 0) {
		noauth(&r, KHTTP_401);
		khttp_puts(&r, "badauth");
		khttp_free(&r);
		if (rc != 2)
			free(user);
		return(EXIT_SUCCESS);
	}

	for (i = 0; i < r.fieldsz; i++) {
		p = &(r.fields[i]);
		if (p->state != KPAIR_VALID) {
			resp_open(&r, KHTTP_200);
			khttp_puts(&r, "911");
			khttp_free(&r);
			free(user);
			return(EXIT_SUCCESS);
		}
		if (strcmp(p->key,"myip") == 0) {
			myip = (char*)p->parsed.s;
		}
		if (strcmp(p->key,"name") == 0) {
			name = (char*)p->parsed.s;
		}
		if (strcmp(p->key,"ttl") == 0) {
			x = p->parsed.i;
			/* make sure we are not to big or small */
			if (x < 300 || x > INTMAX_MAX) {
				resp_open(&r, KHTTP_200);
				khttp_puts(&r, "911");
				khttp_free(&r);
				free(user);
				return(EXIT_SUCCESS);
			}
			if ((asprintf(&ttl, "%llu", x)) < 0) {
				/* error with allocating string */
				resp_open(&r, KHTTP_200);
				khttp_puts(&r, "911");
				khttp_free(&r);
				free(user);
				return(EXIT_SUCCESS);
			}
		}
	}
	if (myip == NULL) {
		resp_open(&r, KHTTP_200);
		khttp_puts(&r, "noip");
		khttp_free(&r);
		free(user);
		return(EXIT_SUCCESS);
	}
	if (name == NULL) {
		resp_open(&r, KHTTP_200);
		khttp_puts(&r, "nohost");
		khttp_free(&r);
		free(user);
		return(EXIT_SUCCESS);
	}
	if (ttl == NULL) {
		if ((ttl = strdup(DEFAULT_TTL)) == NULL) {
			/* not memory */
			resp_open(&r, KHTTP_200);
			khttp_puts(&r, "911");
			khttp_free(&r);
			free(user);
			return(EXIT_FAILURE);
		}
	}

	resp_open(&r, KHTTP_200);
	rc = save_request(&r, user, name, myip, ttl);
	switch (rc) {
	case 1:	/* updated */
		khttp_puts(&r, "good");
		break;
	case 0:	/* no change */
		khttp_puts(&r, "nochg");
		break;
	default: /* rc < 0 */
//		khttp_puts(&r, "dnserr");
		khttp_puts(&r, "911");
		break;
	}

	khttp_free(&r);
	if (user)
		free(user);
	if (ttl)
		free(ttl);
	return(EXIT_SUCCESS);
}

