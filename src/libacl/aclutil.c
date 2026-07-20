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

