/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef AFS_SRC_VENUS_ACLUTIL_H
#define AFS_SRC_VENUS_ACLUTIL_H

#include <afs/afs_consts.h>
#include <afs/stds.h>

#define MAXNAME 100

typedef char sec_rgy_name_t[1025];	/* A DCE definition */

enum rtype {
    add,	/**< overwrite/set rights ('=' default behavior) */
    destroy,	/**< remove the ACL entirely ("none") */
    deny,	/**< revoke all rights ("null" DFS specific) */
    reladd,	/**< add specific rights to existing ones ('+') */
    reldel	/**< remove specific rights from existing ones ('-') */
};

struct AclEntry {
    struct AclEntry *next;
    char name[MAXNAME];
    afs_int32 rights;
};

struct Acl {
    int dfs;			/* Originally true if a dfs acl; now also the
				 * type of the acl (1, 2, or 3, corresponding to
				 * object, initial dir, or initial object). */
    sec_rgy_name_t cell;	/* DFS cell name */
    int nplus;
    int nminus;
    struct AclEntry *pluslist;
    struct AclEntry *minuslist;
};

struct acl_stringbuf {
    char sbuf[22];
};

char *aclutil_StringifyRights(afs_int32 rights, int is_dfs,
			      struct acl_stringbuf *a_strbuf);
int aclutil_AclToString(const struct Acl *acl, char *a_acl_str, size_t len);
int aclutil_ParseRights(const char *rights, int is_dfs,
			enum rtype *a_rights_type, afs_int32 *a_rights_mask,
			int *a_error_offset);
int aclutil_CleanAcl(struct Acl *aa, char *cellname);
int aclutil_ChangeList(struct Acl *al, afs_int32 plus, const char *aname,
		       afs_int32 arights, const enum rtype *artypep);
struct AclEntry *aclutil_FindList(struct AclEntry *alist, const char *aname);
int aclutil_ParseAcl(const char *astr, struct Acl **a_acl);
int aclutil_EmptyAcl(const char *astr, struct Acl **a_acl);
void aclutil_ZapAcl(struct Acl **a_acl);

#endif /* AFS_SRC_VENUS_ACLUTIL_H */