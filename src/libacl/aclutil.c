/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <ctype.h>
#include <assert.h>
#include <afs/ptuser.h>
#include <afs/ptclient.h>
#include <afs/dirpath.h>

#include "acl.h"
#include "prs_fs.h"

struct acl_shorthand {
    const char *name;
    afs_int32 mask;
};

static const struct acl_shorthand afs_shorthand[] = {
    { "read",  PRSFS_READ   | PRSFS_LOOKUP },
    { "mail",  PRSFS_INSERT | PRSFS_LOCK   | PRSFS_LOOKUP },
    { "write", PRSFS_READ   | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
	       PRSFS_WRITE  | PRSFS_LOCK },
    { "all",   PRSFS_READ   | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
	       PRSFS_WRITE  | PRSFS_LOCK   | PRSFS_ADMINISTER },
    { NULL, 0 }
};

static const afs_int32 afs_bitmap[256] = {
    ['r'] = PRSFS_READ,
    ['l'] = PRSFS_LOOKUP,
    ['i'] = PRSFS_INSERT,
    ['d'] = PRSFS_DELETE,
    ['w'] = PRSFS_WRITE,
    ['k'] = PRSFS_LOCK,
    ['a'] = PRSFS_ADMINISTER,
    ['A'] = PRSFS_USR0,
    ['B'] = PRSFS_USR1,
    ['C'] = PRSFS_USR2,
    ['D'] = PRSFS_USR3,
    ['E'] = PRSFS_USR4,
    ['F'] = PRSFS_USR5,
    ['G'] = PRSFS_USR6,
    ['H'] = PRSFS_USR7
};

static const struct acl_shorthand dfs_shorthand[] = {
    { "read",  DFS_READ | DFS_EXECUTE },
    { "write", DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE | DFS_WRITE },
    { "all",   DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE | DFS_WRITE |
	       DFS_CONTROL },
    { NULL, 0 }
};

static const afs_int32 dfs_bitmap[256] = {
    ['r'] = DFS_READ,
    ['w'] = DFS_WRITE,
    ['x'] = DFS_EXECUTE,
    ['c'] = DFS_CONTROL,
    ['i'] = DFS_INSERT,
    ['d'] = DFS_DELETE,
    ['A'] = DFS_USR0,
    ['B'] = DFS_USR1,
    ['C'] = DFS_USR2,
    ['D'] = DFS_USR3,
    ['E'] = DFS_USR4,
    ['F'] = DFS_USR5,
    ['G'] = DFS_USR6,
    ['H'] = DFS_USR7
};

/**
 * Converts an ACL bitmask into a human-readable string.
 *
 * Translates an internal bitmask of access rights into a string representation.
 * The output format is determined by whether the rights are AFS or DFS.
 *
 * @param[in]  rights   bitmask of access rights to stringify
 * @param[in]  is_dfs   non-zero if the rights are DFS
 * @param[out] a_strbuf caller-provided output buffer
 *
 * @return null-terminated human-readable string
 */
char *
acl_StringifyRights(afs_int32 rights, int is_dfs,
		    struct acl_stringbuf *a_strbuf)
{
    int idx, buf_i;
    int use_placeholder;
    const char *bitmap_order;
    const afs_int32 *bitmap_table;

    if (a_strbuf == NULL) {
	return "(null)";
    }

    memset(a_strbuf, 0, sizeof(*a_strbuf));

    if (is_dfs) {
	bitmap_order = "rwxcidABCDEFGH";
	bitmap_table = dfs_bitmap;
	use_placeholder = 1;
    } else {
	bitmap_order = "rlidwkaABCDEFGH";
	bitmap_table = afs_bitmap;
	use_placeholder = 0;
    }

    buf_i = 0;
    for (idx = 0; bitmap_order[idx] != '\0'; idx++) {
	unsigned char rc = bitmap_order[idx];
	if (is_dfs && rc == 'A') {
	    if ((rights & DFS_USRALL) != 0) {
		a_strbuf->sbuf[buf_i] = '+';
		buf_i++;
	    }
	    use_placeholder = 0;
	}
	if ((rights & bitmap_table[rc]) != 0) {
	    a_strbuf->sbuf[buf_i] = rc;
	    buf_i++;
	} else if (use_placeholder) {
	    a_strbuf->sbuf[buf_i] = '-';
	    buf_i++;
	}
    }

    return a_strbuf->sbuf;
}

/**
 * Parses an ACL rights string into a bitmask.
 *
 * Translates user-provided string of access rights into the internal bitmask
 * representation. It handles abbreviations (e.g. rlidwka) and shorthands
 * (e.g. read). It also inspects the string for trailing modifiers (+, -,
 * =) to determine whether the rights should be added to, removed from, or
 * explicitly overwrite the existing ACL entry.
 *
 * @param[in]   rights          null-terminated string representing the rights
 * @param[in]   is_dfs          non-zero if parsing DCE DFS access rights
 * @param[out]  a_rights_type   resolved ACL action
 * @param[out]  a_rights_mask   calculated rights bitmask
 * @param[out]  a_error_index   index of the first illegal char encountered
 *
 * @return status codes
 *   @retval 0       success
 *   @retval EINVAL  NULL argument or unrecognized character
 */
int
acl_ParseRights(const char *rights, int is_dfs, enum rtype *a_rights_type,
		afs_int32 *a_rights_mask, int *a_error_index)
{
    size_t idx;
    size_t rights_len;
    afs_int32 mode = 0;
    const afs_int32 *bitmap;
    const struct acl_shorthand *shorthand;

    if (a_error_index != NULL) {
	*a_error_index = -1;
    }
    if (rights == NULL || a_rights_type == NULL || a_rights_mask == NULL) {
	return EINVAL;
    }

    /* default behavior */
    *a_rights_type = add;

    rights_len = strlen(rights);
    if (rights_len > 0) {
	char type = rights[rights_len - 1];
	switch (type) {
	case '+':
	    *a_rights_type = reladd;
	    rights_len--;
	    break;
	case '-':
	    *a_rights_type = reldel;
	    rights_len--;
	    break;
	case '=':
	    *a_rights_type = add;
	    rights_len--;
	    break;
	}
    }

    /* special cases */
    if (is_dfs) {
	if (rights_len == strlen("null") &&
	    strncmp(rights, "null", rights_len) == 0) {
	    *a_rights_type = deny;
	    *a_rights_mask = 0;
	    return 0;
	}
    }
    if (rights_len == strlen("none") &&
	strncmp(rights, "none", rights_len) == 0) {
	*a_rights_type = destroy;
	*a_rights_mask = 0;
	return 0;
    }

    if (is_dfs) {
	bitmap = dfs_bitmap;
	shorthand = dfs_shorthand;
    } else {
	bitmap = afs_bitmap;
	shorthand = afs_shorthand;
    }

    /* check if a shorthand was given first */
    for (idx = 0; shorthand[idx].name != NULL; idx++) {
	if (rights_len != strlen(shorthand[idx].name)) {
	    continue;
	}
	if (strncmp(rights, shorthand[idx].name, rights_len) == 0) {
	    *a_rights_mask = shorthand[idx].mask;
	    return 0;
	}
    }

    /* if no shorthand was found, check for abbreviations */
    for (idx = 0; idx < rights_len; idx++) {
	unsigned char rc = rights[idx];
	afs_int32 mask = bitmap[rc];

	/* special case */
	if (is_dfs && rc == '-') {
	    continue;
	}
	if (mask == 0) {
	    if (a_error_index != NULL && idx <= (size_t)INT_MAX) {
		*a_error_index = (int)idx;
	    }
	    return EINVAL;
	}
	mode |= mask;
    }

    *a_rights_mask = mode;

    return 0;
}

/* Check if a username is valid: If it contains only digits (or a
 * negative sign), then it might be bad. We then query the ptserver
 * to see.
 */
static int
BadName(char *aname, char *cellname)
{
    afs_int32 tc, code, id;
    char *nm;

    for (nm = aname; (tc = *nm); nm++) {
	/* all must be '-' or digit to be bad */
	if (tc != '-' && (tc < '0' || tc > '9'))
	    return 0;
    }

    /* Go to the PRDB and see if this all number username is valid */
    code = pr_Initialize(1, AFSDIR_CLIENT_ETC_DIRPATH, cellname);
    if (code != 0) {
	return 0;
    }

    code = pr_SNameToId(aname, &id);
    pr_End();

    if (code != 0) {
	return 0;
    }

    /* 1=>Not-valid; 0=>Valid */
    return (id == ANONYMOUSID) ? 1 : 0;
}

/**
 * Cleans an ACL of stale entries via protection server queries.
 *
 * Enumerates the given ACL struct's list of ACL entries, checking for names
 * that strictly consist only of digits or a leading minus, since these entries
 * have the potential to be stale. This is since such stale entries cannot have
 * their UIDs translated to names by the File Server without a protection server
 * entry.
 *
 * @param[in,out]  aa       Acl struct to clean
 * @param[in]      cellname null-terminated string holding the cell name
 *
 * @return number of changes made to ACL
 */
int
acl_CleanAcl(struct Acl *aa, char *cellname)
{
    struct AclEntry *te, **le, *ne;
    int changes;

    /* Don't correct DFS ACL's for now */
    if (aa->dfs)
	return 0;

    /* prune out bad entries */
    changes = 0;		/* count deleted entries */
    le = &aa->pluslist;
    for (te = aa->pluslist; te; te = ne) {
	ne = te->next;
	if (BadName(te->name, cellname)) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nplus--;
	    free(te);
	    changes++;
	} else {
	    le = &te->next;
	}
    }
    le = &aa->minuslist;
    for (te = aa->minuslist; te; te = ne) {
	ne = te->next;
	if (BadName(te->name, cellname)) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nminus--;
	    free(te);
	    changes++;
	} else {
	    le = &te->next;
	}
    }
    return changes;
}

static int
foldcmp(const char *a, const char *b)
{
    char t, u;
    while (1) {
	t = *a++;
	u = *b++;
	if (t >= 'A' && t <= 'Z')
	    t += 0x20;
	if (u >= 'A' && u <= 'Z')
	    u += 0x20;
	if (t != u)
	    return 1;
	if (t == 0)
	    return 0;
    }
}

/**
 * Finds an ACL entry of a given name in a linked list of ACL entries.
 *
 * @param[in]  alist pointer to first linked list node to search
 * @param[in]  aname null-terminated string holding the name to find
 *
 * @retval non-NULL pointer to AclEntry with the given name
 * @retval NULL     no entry with given name exists
 */
struct AclEntry *
acl_FindList(struct AclEntry *alist, const char *aname)
{
    while (alist) {
	if (!foldcmp(alist->name, aname))
	    return alist;
	alist = alist->next;
    }
    return 0;
}

static int
PruneList(struct AclEntry **ae, int dfs)
{
    struct AclEntry **lp;
    struct AclEntry *te, *ne;
    afs_int32 ctr;
    ctr = 0;
    lp = ae;
    for (te = *ae; te; te = ne) {
	if ((!dfs && te->rights == 0) || te->rights == -1) {
	    *lp = te->next;
	    ne = te->next;
	    free(te);
	    ctr++;
	} else {
	    ne = te->next;
	    lp = &te->next;
	}
    }
    return ctr;
}

/**
 * Modifies given ACL according to given arguments.
 *
 * Locates ACL entry with name given in aname. If an entry with the name given
 * does not exist, and the rtype given is not reldel, a new entry will be
 * created and inserted. If reldel was given, nothing will happen rights
 * cannot be removed from a nonexistent entry.
 *
 * Entries with 0 rights after the change will be deleted.
 *
 * @param[in,out]  al      Acl struct to modify
 * @param[in]      plus    0 indicates modifying the negative list, nonzero
 *			   indicates modifying the positive list
 * @param[in]      aname   name of the AclEntry to modify/create
 * @param[in]      arights rights bitmask to apply
 * @param[in]      artypep method to incorporate arights with
 *			   (see enum rtype: set, reladd, reldel, etc.)
 *
 * @return status codes
 * @retval 0 success
 * @retval ENOMEM calloc call failed, insufficient memory
 * @retval EINVAL passed in aname argument was too long, causing truncation, or
 *		  the passed enum type is invalid
 */
int
acl_ChangeList(struct Acl *al, afs_int32 plus, const char *aname,
	       afs_int32 arights, const enum rtype *artypep)
{
    size_t namelen;
    struct AclEntry *tentry;

    if (plus) {
	tentry = acl_FindList(al->pluslist, aname);
    } else {
	tentry = acl_FindList(al->minuslist, aname);
    }

    if (tentry != NULL) {
	/*
	 * Found the item already in the list. Modify rights in case of reladd
	 * and reladd only, use standard - add, ie. set - otherwise
	 */
	if (artypep == NULL) {
	    tentry->rights = arights;
	} else {
	    switch (*artypep) {
	    case reladd:
		tentry->rights |= arights;
		break;
	    case reldel:
		tentry->rights &= ~arights;
		break;
	    case add:
	    case destroy:
	    case deny:
		tentry->rights = arights;
		break;
	    default:
		return EINVAL;
	    }
	}

	if (plus) {
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
	} else {
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
	}
	return 0;
    }
    if (artypep != NULL && *artypep == reldel) {
	return 0;                 /* can't reduce non-existing rights   */
    }

    /* Otherwise we make a new item and plug in the new data. */
    tentry = calloc(1, sizeof(*tentry));
    if (tentry == NULL) {
	return ENOMEM;
    }

    namelen = strlcpy(tentry->name, aname, sizeof(tentry->name));
    if (namelen >= sizeof(tentry->name)) {
	free(tentry);
	return EINVAL;
    }

    tentry->rights = arights;

    if (plus) {
	tentry->next = al->pluslist;
	al->pluslist = tentry;
	al->nplus++;
	if (arights == 0 || arights == -1) {
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
	}
    } else {
	tentry->next = al->minuslist;
	al->minuslist = tentry;
	al->nminus++;
	if (arights == 0) {
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
	}
    }
    return 0;
}

static const char *
SkipLine(const char *astr)
{
    while (*astr != '\0' && *astr != '\n')
	astr++;
    if (*astr == '\n')
	astr++;
    return astr;
}

/**
 * Creates a new Acl struct from an ACL string.
 *
 * The expected format of the input string is the standard AFS ACL string
 * format. The first two lines are formatted as follows:
 *
 * <nplus> [dfs:<type> <cell>]
 * <nminus>
 *
 * The dfs:<type> <cell> portion of the first line is only present for DFS ACLs,
 * AFS ACLs omit this part.
 *
 * The next nplus lines represent the positive entries, formatted as
 * <name> <rights>, where <rights> is an integer rights bitmask. The same is
 * true for the following nminus lines after the last line representing a
 * positive entry.
 *
 * The caller is responsible for freeing the newly created Acl struct by
 * invoking acl_ZapAcl.
 *
 * @param[in]  astr  ACL string to construct the Acl struct from
 * @param[out] a_acl address of the resulting Acl struct
 *
 * @return status codes
 * @retval 0      success
 * @retval EINVAL astr or a_acl was NULL, or astr was malformed
 * @retval ENOMEM allocation failed, insufficient memory
 */
int
acl_ParseAcl(const char *astr, struct Acl **a_acl)
{
    size_t namelen;
    int code;
    int nplus = 0, nminus = 0, i, trights = 0;
    char tname[MAXNAME + 1] = "";
    struct AclEntry *last, *tl;
    struct Acl *ta = NULL;

    if (astr == NULL || a_acl == NULL) {
	code = EINVAL;
	goto done;
    }
    *a_acl = NULL;

    ta = calloc(sizeof(*ta), 1);
    if (ta == NULL) {
	code = ENOMEM;
	goto done;
    }

    code = sscanf(astr, "%d dfs:%d %1024s", &ta->nplus, &ta->dfs, ta->cell);
    /* A DCE/DFS header would result in 3, a regular AFS header 1 */
    if (code != 1 && code != 3) {
	code = EINVAL;
	goto done;
    }

    astr = SkipLine(astr);
    code = sscanf(astr, "%d", &ta->nminus);
    if (code != 1) {
	code = EINVAL;
	goto done;
    }

    astr = SkipLine(astr);

    nplus = ta->nplus;

    last = NULL;
    for (i = 0; i < nplus; i++) {
	code = sscanf(astr, "%99s %d", tname, &trights);
	if (code != 2) {
	    code = EINVAL;
	    goto done;
	}

	astr = SkipLine(astr);
	tl = calloc(sizeof(*tl), 1);
	if (tl == NULL) {
	    code = ENOMEM;
	    goto done;
	}

	namelen = strlcpy(tl->name, tname, sizeof(tl->name));
	if (namelen >= sizeof(tl->name)) {
	    free(tl);
	    code = EINVAL;
	    goto done;
	}

	if (ta->pluslist == NULL) {
	    ta->pluslist = tl;
	}

	tl->rights = trights;
	tl->next = NULL;
	if (last != NULL) {
	    last->next = tl;
	}
	last = tl;
    }

    nminus = ta->nminus;

    last = NULL;
    for (i = 0; i < nminus; i++) {
	code = sscanf(astr, "%99s %d", tname, &trights);
	if (code != 2) {
	    code = EINVAL;
	    goto done;
	}

	astr = SkipLine(astr);
	tl = calloc(sizeof(*tl), 1);
	if (tl == NULL) {
	    code = ENOMEM;
	    goto done;
	}

	namelen = strlcpy(tl->name, tname, sizeof(tl->name));
	if (namelen >= sizeof(tl->name)) {
	    free(tl);
	    code = EINVAL;
	    goto done;
	}

	if (ta->minuslist == NULL) {
	    ta->minuslist = tl;
	}

	tl->rights = trights;
	tl->next = NULL;
	if (last != NULL) {
	    last->next = tl;
	}
	last = tl;
    }

    *a_acl = ta;
    code = 0;

done:
    if (code != 0) {
	acl_ZapAcl(&ta);
    }
    return code;
}

/**
 * Creates an empty Acl struct, using an ACL string to obtain DFS information.
 *
 * The only part of the input string that is parsed is the first line, since
 * that is the part containing DFS information, and so that bogus ACLs can be
 * recovered from. See acl_ParseAcl for information on expected ACL string
 * format.
 *
 * The caller is responsible for freeing the newly created Acl struct by
 * invoking acl_ZapAcl.
 *
 * @param[in]  astr  ACL string to mimic the DFS status and cell from
 * @param[out] a_acl address of the resulting Acl struct
 *
 * @return status codes
 * @retval 0      success
 * @retval EINVAL astr or a_acl was NULL, or malformed header line for astr
 * @retval ENOMEM allocation failed, insufficient memory
 */
int
acl_EmptyAcl(const char *astr, struct Acl **a_acl)
{
    struct Acl *tp = NULL;
    int code, junk;

    if (astr == NULL || a_acl == NULL) {
	return EINVAL;
    }

    tp = calloc(sizeof(*tp), 1);
    if (tp == NULL) {
	return ENOMEM;
    }
    code = sscanf(astr, "%d dfs:%d %1024s", &junk, &tp->dfs, tp->cell);
    /* A DCE/DFS header would result in 3, a regular AFS header 1 */
    if (code != 1 && code != 3) {
	free(tp);
	return EINVAL;
    }

    *a_acl = tp;
    return 0;
}

/**
 * Converts an Acl data structure into a string.
 *
 * Serializes a user-provided Acl struct into a string. May be used for storing
 * or displaying ACLs.
 *
 * @param[in]   acl             the Acl struct to be converted
 * @param[out]  a_acl_str       resulting ACL string, contents undefined on
 *				failure
 * @param[in]   len             length of the output buffer a_acl_str, should be
 *				at least AFS_PIOCTL_MAXSIZE + 24 to guarantee
 *				sufficient space
 *
 * @return status codes
 * @retval 0 success
 * @retval EINVAL provided buffer or Acl struct is NULL
 * @retval ENOSPC truncation occurred while assembling string
 */
int
acl_AclToString(const struct Acl *acl, char *a_acl_str, size_t len)
{
    char *buf = a_acl_str;
    struct AclEntry *entry;
    int offset;
    size_t bsize = len;

    if (buf == NULL || acl == NULL) {
	return EINVAL;
    }

    memset(buf, 0, bsize);

    offset = snprintf(buf, bsize, "%d", acl->nplus);
    if (offset < 0 || (size_t)offset >= bsize) {
	return ENOSPC;
    }

    buf += offset;
    bsize -= offset;

    if (acl->dfs) {
	offset = snprintf(buf, bsize, " dfs:%d %s", acl->dfs, acl->cell);
	if (offset < 0 || (size_t)offset >= bsize) {
	    return ENOSPC;
	}
	buf += offset;
	bsize -= offset;
    }

    offset = snprintf(buf, bsize, "\n%d\n", acl->nminus);
    if (offset < 0 || (size_t)offset >= bsize) {
	return ENOSPC;
    }

    buf += offset;
    bsize -= offset;

    for (entry = acl->pluslist; entry != NULL; entry = entry->next) {
	offset = snprintf(buf, bsize, "%s %d\n", entry->name, entry->rights);
	if (offset < 0 || (size_t)offset >= bsize) {
	    return ENOSPC;
	}
	buf += offset;
	bsize -= offset;
    }
    for (entry = acl->minuslist; entry != NULL; entry = entry->next) {
	offset = snprintf(buf, bsize, "%s %d\n", entry->name, entry->rights);
	if (offset < 0 || (size_t)offset >= bsize) {
	    return ENOSPC;
	}
	buf += offset;
	bsize -= offset;
    }
    return 0;
}

static void
ZapList(struct AclEntry *alist)
{
    struct AclEntry *tp, *np;
    for (tp = alist; tp; tp = np) {
	np = tp->next;
	free(tp);
    }
}

/**
 * Frees an Acl struct and all of its entries.
 *
 * If the pointed-to Acl struct is NULL, the function does nothing. On return,
 * the caller's pointer (*a_acl) is set to NULL to avoid dangling pointers.
 *
 * @param[in,out] a_acl address of the Acl struct pointer to be freed, this Acl
 *			struct pointer (*a_acl) is set to NULL on return
 */
void
acl_ZapAcl(struct Acl **a_acl)
{
    struct Acl *acl;

    if (a_acl == NULL || *a_acl == NULL) {
	return;
    }
    acl = *a_acl;

    ZapList(acl->pluslist);
    ZapList(acl->minuslist);
    free(acl);

    *a_acl = NULL;
}