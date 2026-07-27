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

#include "acl.h"
#include "prs_fs.h"

static int
ParseRights(int dfs, const char *rights_str, afs_uint32 *a_mask,
	    enum aclu_rights_type *rtypep, char *bad_char)
{
    afs_int32 mode;
    int code;
    int tc_i;
    char tc;
    char *tcp;                  /* to walk through the rights string  */
    char *arights = NULL;

    if (bad_char != NULL) {
	*bad_char = 0;
    }

    if (rights_str == NULL || a_mask == NULL || rtypep == NULL) {
	code = EINVAL;
	goto error;
    }

    arights = strdup(rights_str);
    if (arights == NULL) {
	code = ENOMEM;
	goto error;
    }

    /* set rights by default */
    *rtypep = ACLU_RTYPE_SET;

                                /* analyze last character of string   */
    tcp = arights + strlen(arights);
    if ( tcp-- > arights ) {    /* assure non-empty string            */
        if ( *tcp == '+' )
	    *rtypep = ACLU_RTYPE_RELADD;   /* '+' indicates more rights          */
        else if ( *tcp == '-' )
	    *rtypep = ACLU_RTYPE_RELDEL;   /* '-' indicates less rights          */
        else if ( *tcp == '=' )
	    *rtypep = ACLU_RTYPE_SET;      /* '=' also allows old behaviour      */
        else
            tcp++;              /* back to original null byte         */
        *tcp = '\0';            /* do not disturb old strcmp-s        */
    }

    if (dfs) {
	if (!strcmp(arights, "null")) {
	    *rtypep = ACLU_RTYPE_DENY;
	    mode = 0;
	    goto success;
	}
	if (!strcmp(arights, "read")) {
	    mode = DFS_READ | DFS_EXECUTE;
	    goto success;
	}
	if (!strcmp(arights, "write")) {
	    mode = DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE |
		DFS_WRITE;
	    goto success;
	}
	if (!strcmp(arights, "all")) {
	    mode = DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE |
		DFS_WRITE | DFS_CONTROL;
	    goto success;
	}
    } else {
	if (!strcmp(arights, "read")) {
	    mode = PRSFS_READ | PRSFS_LOOKUP;
	    goto success;
	}
	if (!strcmp(arights, "write")) {
	    mode = PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
		PRSFS_WRITE | PRSFS_LOCK;
	    goto success;
	}
	if (!strcmp(arights, "mail")) {
	    mode = PRSFS_INSERT | PRSFS_LOCK | PRSFS_LOOKUP;
	    goto success;
	}
	if (!strcmp(arights, "all")) {
	    mode = PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
		PRSFS_WRITE | PRSFS_LOCK | PRSFS_ADMINISTER;
	    goto success;
	}
    }
    if (!strcmp(arights, "none")) {
	*rtypep = ACLU_RTYPE_DESTROY;	/* Remove entire entry */
	mode = 0;
	goto success;
    }
    mode = 0;
    for (tc_i = 0; arights[tc_i] != '\0'; tc_i++) {
	tc = arights[tc_i];

	if (dfs) {
	    if (tc == '-')
		continue;
	    else if (tc == 'r')
		mode |= DFS_READ;
	    else if (tc == 'w')
		mode |= DFS_WRITE;
	    else if (tc == 'x')
		mode |= DFS_EXECUTE;
	    else if (tc == 'c')
		mode |= DFS_CONTROL;
	    else if (tc == 'i')
		mode |= DFS_INSERT;
	    else if (tc == 'd')
		mode |= DFS_DELETE;
	    else if (tc == 'A')
		mode |= DFS_USR0;
	    else if (tc == 'B')
		mode |= DFS_USR1;
	    else if (tc == 'C')
		mode |= DFS_USR2;
	    else if (tc == 'D')
		mode |= DFS_USR3;
	    else if (tc == 'E')
		mode |= DFS_USR4;
	    else if (tc == 'F')
		mode |= DFS_USR5;
	    else if (tc == 'G')
		mode |= DFS_USR6;
	    else if (tc == 'H')
		mode |= DFS_USR7;
	    else {
		if (bad_char != NULL) {
		    *bad_char = tc;
		}
		code = EINVAL;
		goto error;
	    }
	} else {
	    if (tc == 'r')
		mode |= PRSFS_READ;
	    else if (tc == 'l')
		mode |= PRSFS_LOOKUP;
	    else if (tc == 'i')
		mode |= PRSFS_INSERT;
	    else if (tc == 'd')
		mode |= PRSFS_DELETE;
	    else if (tc == 'w')
		mode |= PRSFS_WRITE;
	    else if (tc == 'k')
		mode |= PRSFS_LOCK;
	    else if (tc == 'a')
		mode |= PRSFS_ADMINISTER;
	    else if (tc == 'A')
		mode |= PRSFS_USR0;
	    else if (tc == 'B')
		mode |= PRSFS_USR1;
	    else if (tc == 'C')
		mode |= PRSFS_USR2;
	    else if (tc == 'D')
		mode |= PRSFS_USR3;
	    else if (tc == 'E')
		mode |= PRSFS_USR4;
	    else if (tc == 'F')
		mode |= PRSFS_USR5;
	    else if (tc == 'G')
		mode |= PRSFS_USR6;
	    else if (tc == 'H')
		mode |= PRSFS_USR7;
	    else {
		if (bad_char != NULL) {
		    *bad_char = tc;
		}
		code = EINVAL;
		goto error;
	    }
	}
    }

 success:
    *a_mask = mode;
    code = 0;

 error:
    free(arights);
    return code;
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
 * @param[in]   arights  null-terminated string representing the rights
 * @param[out]  a_mask   calculated rights bitmask
 * @param[out]  rtypep   resolved ACL action
 * @param[out]  bad_char pointer to the first illegal char encountered
 *
 * @return status codes
 * @retval 0       success
 * @retval EINVAL  NULL argument or unrecognized character
 */
int
aclu_ParseRights(const char *arights, afs_uint32 *a_mask,
		 enum aclu_rights_type *rtypep, char *bad_char)
{
    return ParseRights(0, arights, a_mask, rtypep, bad_char);
}

/**
 * Parses an DFS ACL rights string into a bitmask.
 *
 * Has the same function as aclu_ParseRights, but for DFS ACLs. See comment
 * above aclu_ParseRights for details on supported function.
 *
 * @param[in]   arights  null-terminated string representing the rights
 * @param[out]  a_mask   calculated rights bitmask
 * @param[out]  rtypep   resolved ACL action
 * @param[out]  bad_char pointer to the first illegal char encountered
 *
 * @return status codes
 * @retval 0       success
 * @retval EINVAL  NULL argument or unrecognized character
 */
int
aclu_ParseRightsDFS(const char *arights, afs_uint32 *a_mask,
		    enum aclu_rights_type *rtypep, char *bad_char)
{
    return ParseRights(1, arights, a_mask, rtypep, bad_char);
}

/**
 * Converts an ACL bitmask into a human-readable string.
 *
 * Translates an internal bitmask of access rights into a string representation.
 *
 * @param[in]  arights bitmask of access rights to stringify
 * @param[out] strbuf  caller-provided output buffer
 *
 * @return null-terminated human-readable string
 */
const char *
aclu_StringifyRights(afs_uint32 arights, struct aclu_rightsbuf *strbuf)
{
    char *cur = strbuf->sbuf;

    memset(strbuf, 0, sizeof(*strbuf));

    if (arights & PRSFS_READ)
	*cur++ = 'r';
    if (arights & PRSFS_LOOKUP)
	*cur++ = 'l';
    if (arights & PRSFS_INSERT)
	*cur++ = 'i';
    if (arights & PRSFS_DELETE)
	*cur++ = 'd';
    if (arights & PRSFS_WRITE)
	*cur++ = 'w';
    if (arights & PRSFS_LOCK)
	*cur++ = 'k';
    if (arights & PRSFS_ADMINISTER)
	*cur++ = 'a';
    if (arights & PRSFS_USR0)
	*cur++ = 'A';
    if (arights & PRSFS_USR1)
	*cur++ = 'B';
    if (arights & PRSFS_USR2)
	*cur++ = 'C';
    if (arights & PRSFS_USR3)
	*cur++ = 'D';
    if (arights & PRSFS_USR4)
	*cur++ = 'E';
    if (arights & PRSFS_USR5)
	*cur++ = 'F';
    if (arights & PRSFS_USR6)
	*cur++ = 'G';
    if (arights & PRSFS_USR7)
	*cur++ = 'H';

    return strbuf->sbuf;
}


/**
 * Converts an DFS ACL bitmask into a human-readable string.
 *
 * Translates an internal bitmask of access rights into a string representation.
 * Output format is that of DFS ACLs.
 *
 * @param[in]  arights bitmask of access rights to stringify
 * @param[out] strbuf  caller-provided output buffer
 *
 * @return null-terminated human-readable string
 */
const char *
aclu_StringifyRightsDFS(afs_uint32 arights, struct aclu_rightsbuf *strbuf)
{
    char *cur = strbuf->sbuf;

    memset(strbuf, 0, sizeof(*strbuf));

    if (arights & DFS_READ)
	*cur++ = 'r';
    else
	*cur++ = '-';
    if (arights & DFS_WRITE)
	*cur++ = 'w';
    else
	*cur++ = '-';
    if (arights & DFS_EXECUTE)
	*cur++ = 'x';
    else
	*cur++ = '-';
    if (arights & DFS_CONTROL)
	*cur++ = 'c';
    else
	*cur++ = '-';
    if (arights & DFS_INSERT)
	*cur++ = 'i';
    else
	*cur++ = '-';
    if (arights & DFS_DELETE)
	*cur++ = 'd';
    else
	*cur++ = '-';
    if (arights & (DFS_USRALL))
	*cur++ = '+';
    if (arights & DFS_USR0)
	*cur++ = 'A';
    if (arights & DFS_USR1)
	*cur++ = 'B';
    if (arights & DFS_USR2)
	*cur++ = 'C';
    if (arights & DFS_USR3)
	*cur++ = 'D';
    if (arights & DFS_USR4)
	*cur++ = 'E';
    if (arights & DFS_USR5)
	*cur++ = 'F';
    if (arights & DFS_USR6)
	*cur++ = 'G';
    if (arights & DFS_USR7)
	*cur++ = 'H';

    return strbuf->sbuf;
}

static void
FreeEntryList(struct aclu_AclEntry *alist)
{
    struct aclu_AclEntry *tp, *np;
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
aclu_FreeAcl(struct aclu_Acl **a_acl)
{
    struct aclu_Acl *acl = *a_acl;
    if (acl == NULL) {
	return;
    }
    *a_acl = NULL;

    FreeEntryList(acl->pluslist);
    FreeEntryList(acl->minuslist);
    free(acl);
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
 * Creates an empty Acl struct, using an ACL string to obtain DFS information.
 *
 * The only part of the input string that is parsed is the first line, since
 * that is the part containing DFS information, and so that bogus ACLs can be
 * recovered from. See aclu_ParseAcl for information on expected ACL string
 * format.
 *
 * The caller is responsible for freeing the newly created Acl struct by
 * invoking aclu_FreeAcl.
 *
 * @param[in]  astr  ACL string to mimic the DFS status and cell from
 * @param[out] a_acl address of the resulting Acl struct
 *
 * @return status codes
 * @retval 0      success
 * @retval ENOMEM allocation failed, insufficient memory
 */
int
aclu_ParseEmptyAcl(const char *astr, struct aclu_Acl **a_acl)
{
    struct aclu_Acl *tp;
    int junk;

    tp = calloc(sizeof(*tp), 1);
    if (tp == NULL) {
	return ENOMEM;
    }

    tp->nplus = tp->nminus = 0;
    tp->pluslist = tp->minuslist = 0;
    tp->dfs = 0;
    sscanf(astr, "%d dfs:%d %1024s", &junk, &tp->dfs, tp->cell);

    *a_acl = tp;
    return 0;
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
 * invoking aclu_FreeAcl.
 *
 * @param[in]  astr  ACL string to construct the Acl struct from
 * @param[out] a_acl address of the resulting Acl struct
 *
 * @return status codes
 * @retval 0      success
 * @retval ENOMEM allocation failed, insufficient memory
 */
int
aclu_ParseAcl(const char *astr, struct aclu_Acl **a_acl)
{
    int nplus = 0, nminus = 0, i, trights = 0, code = 0;
    char tname[MAXNAME + 1] = "";
    struct aclu_AclEntry *first, *last, *tl;
    struct aclu_Acl *ta;

    *a_acl = NULL;

    ta = calloc(sizeof(*ta), 1);
    if (ta == NULL) {
	code = ENOMEM;
	goto done;
    }

    ta->dfs = 0;
    sscanf(astr, "%d dfs:%d %1024s", &ta->nplus, &ta->dfs, ta->cell);
    astr = SkipLine(astr);
    sscanf(astr, "%d", &ta->nminus);
    astr = SkipLine(astr);

    nplus = ta->nplus;
    nminus = ta->nminus;

    last = 0;
    first = 0;
    for (i = 0; i < nplus; i++) {
	sscanf(astr, "%99s %d", tname, &trights);
	astr = SkipLine(astr);
	tl = calloc(sizeof(*tl), 1);
	if (tl == NULL) {
	    code = ENOMEM;
	    goto done;
	}
	if (!first) {
	    first = tl;
	    ta->pluslist = first;
	}
	strcpy(tl->name, tname);
	tl->rights = trights;
	tl->next = 0;
	if (last)
	    last->next = tl;
	last = tl;
    }
    ta->pluslist = first;

    last = 0;
    first = 0;
    for (i = 0; i < nminus; i++) {
	sscanf(astr, "%99s %d", tname, &trights);
	astr = SkipLine(astr);
	tl = calloc(sizeof(*tl), 1);
	if (tl == NULL) {
	    code = ENOMEM;
	    goto done;
	}
	if (!first) {
	    first = tl;
	    ta->minuslist = first;
	}
	strcpy(tl->name, tname);
	tl->rights = trights;
	tl->next = 0;
	if (last)
	    last->next = tl;
	last = tl;
    }
    ta->minuslist = first;

    *a_acl = ta;
    code = 0;

 done:
    if (code != 0) {
	aclu_FreeAcl(&ta);
    }
    return code;
}

/**
 * Converts an Acl data structure into a string.
 *
 * Serializes a user-provided Acl struct into a string. May be used for storing
 * or displaying ACLs.
 *
 * @param[in]   acl the Acl struct to be converted
 * @param[out]  buf the buffer to output the string to
 *
 * @return string containing the serialized Acl data
 */
char *
aclu_AclToNetstring(struct aclu_Acl *acl, struct aclu_aclbuf *buf)
{
    char tstring[AFS_PIOCTL_MAXSIZE];
    char dfsstring[AFS_PIOCTL_MAXSIZE];
    struct aclu_AclEntry *tp;

    if (acl->dfs)
	snprintf(dfsstring, sizeof(dfsstring), " dfs:%d %s", acl->dfs, acl->cell);
    else
	dfsstring[0] = '\0';
    snprintf(buf->sbuf, sizeof(buf->sbuf), "%d%s\n%d\n", acl->nplus, dfsstring, acl->nminus);
    for (tp = acl->pluslist; tp; tp = tp->next) {
	snprintf(tstring, sizeof(tstring), "%s %d\n", tp->name, tp->rights);
	strlcat(buf->sbuf, tstring, sizeof(buf->sbuf));
    }
    for (tp = acl->minuslist; tp; tp = tp->next) {
	snprintf(tstring, sizeof(tstring), "%s %d\n", tp->name, tp->rights);
	strlcat(buf->sbuf, tstring, sizeof(buf->sbuf));
    }
    return buf->sbuf;
}

/**
 * Filters an ACL based off a filter function
 *
 * Enumerates the given ACL struct's list of ACL entries, checking for entries
 * that trigger the filter function to set the a_remove variable to 1. Each such
 * entry is removed from the ACL and then freed.
 *
 * @param[in,out]  aa       Acl struct to filter
 * @param[in]      filter   filter function
 * @param[in]      rock     opaque pointer passed to callback
 *
 * @return number of changes made to ACL
 */
int
aclu_FilterAcl(struct aclu_Acl *aa, aclu_filter_func *filter, void *rock)
{
    struct aclu_AclEntry *te, **le, *ne;
    int code;

    /* Don't process DFS ACLs */
    if (aa->dfs)
	return 0;

    le = &aa->pluslist;
    for (te = aa->pluslist; te; te = ne) {
	int remove = 0;
	ne = te->next;
	code = filter(aa, 0, te->name, te->rights, rock, &remove);
	if (code != 0) {
	    return code;
	}
	if (remove) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nplus--;
	    free(te);
	} else {
	    le = &te->next;
	}
    }
    le = &aa->minuslist;
    for (te = aa->minuslist; te; te = ne) {
	int remove = 0;
	ne = te->next;
	code = filter(aa, 1, te->name, te->rights, rock, &remove);
	if (code != 0) {
	    return code;
	}
	if (remove) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nminus--;
	    free(te);
	} else {
	    le = &te->next;
	}
    }
    return 0;
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
struct aclu_AclEntry *
aclu_SearchList(struct aclu_AclEntry *alist, const char *aname)
{
    while (alist) {
	if (!foldcmp(alist->name, aname))
	    return alist;
	alist = alist->next;
    }
    return 0;
}

static int
PruneList(struct aclu_AclEntry **ae, int dfs)
{
    struct aclu_AclEntry **lp;
    struct aclu_AclEntry *te, *ne;
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
 * does not exist, and the rtype given is not ACLU_RELDEL, a new entry will be
 * created and inserted. If ACLU_RELDEL was given, nothing will happen rights
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
 *			   (see enum rtype: ACLU_SET, ACLU_RELADD, etc.)
 *
 * @return status codes
 * @retval 0 success
 * @retval ENOMEM malloc call failed, insufficient memory
 */
int
aclu_UpdateList(struct aclu_Acl *al, afs_int32 plus, const char *aname,
		afs_int32 arights, enum aclu_rights_type *artypep)
{
    struct aclu_AclEntry *tlist = NULL;
    tlist = (plus ? al->pluslist : al->minuslist);
    tlist = aclu_SearchList(tlist, aname);
    if (tlist) {
	/* Found the item already in the list.
	 * modify rights in case of _RELADD and _RELDEL only,
	 * use standard _SET otherwise
	 */
        if ( artypep == NULL )
            tlist->rights = arights;
	else if ( *artypep == ACLU_RTYPE_RELADD )
            tlist->rights |= arights;
	else if ( *artypep == ACLU_RTYPE_RELDEL )
            tlist->rights &= ~arights;
        else
            tlist->rights = arights;

	if (plus)
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
	else
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
	return 0;
    }
    if ( artypep != NULL && *artypep == ACLU_RTYPE_RELDEL )
        return 0;                 /* can't reduce non-existing rights   */

    /* Otherwise we make a new item and plug in the new data. */
    tlist = malloc(sizeof(struct aclu_AclEntry));
    if (tlist == NULL) {
	return ENOMEM;
    }
    strcpy(tlist->name, aname);
    tlist->rights = arights;
    if (plus) {
	tlist->next = al->pluslist;
	al->pluslist = tlist;
	al->nplus++;
	if (arights == 0 || arights == -1)
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
    } else {
	tlist->next = al->minuslist;
	al->minuslist = tlist;
	al->nminus++;
	if (arights == 0)
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
    }

    return 0;
}