/*
 */

#ifndef _MYDYNDNS_H
#define _MYDYNDNS_H

#define DB_FILE "/run/mydyndns.db"

/* db.c */
int db_udpate_domain(struct kreq *r, const char *user, const char *domain, const char *address);
int db_save_domain(struct kreq *r, const char *user, const char *domain, const char *address, const char *ttl, int x);
int db_open(struct kreq *r, const char *file);
void db_close(struct kreq *r);
int db_find_domain(struct kreq *r, char *user, char *domain, char **address, char **ttl);
int db_update_domain(struct kreq *r, char *user, char *domain, char *address, char *ttl);
int db_find_user(struct kreq *r, const char *name, const char *pass);

/* base64.c */
int base64_pton(const char *src, u_char *target, size_t);
int base64_ntop(const u_char *src, size_t srclength, char *target, size_t targetsize);

#endif
