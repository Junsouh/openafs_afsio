/*
 * Copyright (c) 2026 Sine Nomine Associates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/acl.h>
#include <afs/prs_fs.h>

#include <tests/tap/basic.h>
#include "common.h"

/* shorthand 'read' -> rl */
#define READ	(PRSFS_READ | \
		 PRSFS_LOOKUP)

/* shorthand 'write' -> rlidwk */
#define WRITE	(PRSFS_READ   | \
		 PRSFS_LOOKUP | \
		 PRSFS_INSERT | \
		 PRSFS_DELETE | \
		 PRSFS_WRITE  | \
		 PRSFS_LOCK)

/* shorthand 'mail' -> ikl */
#define MAIL	(PRSFS_INSERT | \
		 PRSFS_LOCK   | \
		 PRSFS_LOOKUP)

/* shorthand 'all' -> rlidwka */
#define ALL	(PRSFS_READ   | \
		 PRSFS_LOOKUP | \
		 PRSFS_INSERT | \
		 PRSFS_DELETE | \
		 PRSFS_WRITE  | \
		 PRSFS_LOCK   | \
		 PRSFS_ADMINISTER)

static void
test_ParseRights(void)
{
    int tc_i;
    struct {
	const char *rights_str;
	int code;
	afs_uint32 mask;
	enum aclu_rights_type rtype;
	char bad_char;

    } *tc, test_cases[] = {
	/* rights_str	code	mask	rtype			bad_char*/
	{ "rl",		0,	READ,	ACLU_RTYPE_SET,		0 },
	{ "rlidwk",	0,	WRITE,	ACLU_RTYPE_SET,		0 },
	{ "ikl",	0,	MAIL,	ACLU_RTYPE_SET,		0 },
	{ "rlidwka",	0,	ALL,	ACLU_RTYPE_SET,		0 },
	{ "rlidwk+",	0,	WRITE,	ACLU_RTYPE_RELADD,	0 },
	{ "ikl-",	0,	MAIL,	ACLU_RTYPE_RELDEL,	0 },
	{ "rlidwka=",	0,	ALL,	ACLU_RTYPE_SET,		0 },

	{ "read",	0,	READ,	ACLU_RTYPE_SET,		0 },
	{ "write",	0,	WRITE,	ACLU_RTYPE_SET,		0 },
	{ "mail",	0,	MAIL,	ACLU_RTYPE_SET,		0 },
	{ "all",	0,	ALL,	ACLU_RTYPE_SET,		0 },
	{ "write+",	0,	WRITE,	ACLU_RTYPE_RELADD,	0 },
	{ "mail-",	0,	MAIL,	ACLU_RTYPE_RELDEL,	0 },
	{ "all=",	0,	ALL,	ACLU_RTYPE_SET,		0 },

	{ "foobar",	EINVAL,	0,	0,			'f' },
	{ "rlbogus",	EINVAL,	0,	0,			'b' },
	{ "rlidwka*",	EINVAL,	0,	0,			'*' },
	{ NULL,		EINVAL, 0,	0,			0   },
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	afs_uint32 mask = 0;
	enum aclu_rights_type rtype = 0;
	char bad_char = 0;

	is_int(aclu_ParseRights(tc->rights_str, &mask, &rtype, &bad_char),
	       tc->code, "aclu_ParseRights(%s) == %d",
	       tc->rights_str ? tc->rights_str : "(null)", tc->code);

	if (tc->code == 0) {
	    is_hex(mask, tc->mask, "... mask matches");
	    is_hex(rtype, tc->rtype, "... rtype matches");

	} else {
	    is_hex(bad_char, tc->bad_char, "... bad_char matches");
	}
    }
}

static void
test_StringifyRights(void)
{
    int tc_i;
    struct {
	afs_uint32 rights;
	const char *str;

    } *tc, test_cases[] = {
	{ READ, "rl" },
	{ ALL, "rlidwka"},
	{ 0xffffffff, "rlidwkaABCDEFGH" },
	{ 0, "" },
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	struct aclu_rightsbuf buf;

	is_string(aclu_StringifyRights(tc->rights, &buf), tc->str,
		  "aclu_StringifyRightsAFS(0x%x) == %s",
		  tc->rights, tc->str);
    }
}

struct test_aclu_AclEntry {
    char *name;
    afs_uint32 rights;
};
struct test_aclu_Acl {
    int nplus;
    int nminus;
    struct test_aclu_AclEntry pluslist[20];
    struct test_aclu_AclEntry minuslist[20];

    int dfs;
    char *cell;
};

static int
check_AclEntry(const char *list, int idx, struct aclu_AclEntry *got,
	       struct test_aclu_AclEntry *exp)
{
    if (strcmp(got->name, exp->name) != 0) {
	diag(" left AclEntry %s[%d] name: %s", list, idx, got->name);
	diag("right AclEntry %s[%d] name: %s", list, idx, exp->name);
	return 0;
    }

    if (got->rights != exp->rights) {
	diag(" left AclEntry %s[%d] rights: 0x%x", list, idx, got->rights);
	diag("right AclEntry %s[%d] rights: 0x%x", list, idx, exp->rights);
	return 0;
    }

    return 1;
}

static int
is_acl_v(struct aclu_Acl *got, struct test_aclu_Acl *exp, const char *fmt,
	 va_list ap)
{
    int success, entry_i;
    const char *exp_cell;
    struct aclu_AclEntry *got_entry;

    opr_Assert(exp != NULL);

    if (got == NULL) {
	diag(" left: NULL");
	diag("right: not NULL");
	goto fail;
    }

    if (got->nplus != exp->nplus) {
	diag(" left nplus: %d", got->nplus);
	diag("right nplus: %d", exp->nplus);
	goto fail;
    }

    if (got->nminus != exp->nminus) {
	diag(" left nminus: %d", got->nminus);
	diag("right nminus: %d", exp->nminus);
	goto fail;
    }

    got_entry = got->pluslist;
    for (entry_i = 0; entry_i < got->nplus; entry_i++) {
	if (got_entry == NULL) {
	    goto fail;
	}
	success = check_AclEntry("pluslist", entry_i,
				 got_entry, &exp->pluslist[entry_i]);
	if (!success) {
	    goto fail;
	}
	got_entry = got_entry->next;
    }

    got_entry = got->minuslist;
    for (entry_i = 0; entry_i < got->nminus; entry_i++) {
	if (got_entry == NULL) {
	    goto fail;
	}
	success = check_AclEntry("minuslist", entry_i,
				 got_entry, &exp->minuslist[entry_i]);
	if (!success) {
	    goto fail;
	}
	got_entry = got_entry->next;
    }

    if (got->dfs != exp->dfs) {
	diag(" left dfs: %d", got->dfs);
	diag("right dfs: %d", exp->dfs);
	goto fail;
    }

    exp_cell = exp->cell;
    if (exp_cell == NULL) {
	exp_cell = "";
    }
    if (strcmp(got->cell, exp_cell) != 0) {
	diag(" left cell: %s", got->cell);
	diag("right cell: %s", exp->cell);
	goto fail;
    }

    success = 1;

 done:
    okv(success, fmt, ap);

    return success;

 fail:
    success = 0;
    goto done;
}

static int
is_acl(struct aclu_Acl *got, struct test_aclu_Acl *exp, const char *fmt, ...)
{
    int success;
    va_list args;

    va_start(args, fmt);
    success = is_acl_v(got, exp, fmt, args);
    va_end(args);

    return success;
}

static void
test_ParseAcl(void)
{
    int tc_i;
    struct {
	const char *str;
	int code;
	struct test_aclu_Acl acl;

    } *tc, test_cases[] = {
	{ "2\n0\nsystem:administrators 127\nreaders 9\n", 0,
	    {	2, 0,
		{   { "system:administrators", 127 },
		    { "readers", 9 },
		},
	    },
	},

	{ "1\n1\nsystem:administrators 127\nbadusers 9\n", 0,
	    {	1, 1,
		{{ "system:administrators", 127 }},
		{{ "badusers", 9 }},
	    },
	},

	{ "0\n0\n", 0,
	    { 0, 0 },
	},

	{ "0\n2\nbaduser 0\nworseuser 8\n", 0,
	    { 0, 2,
		{{ 0 }},
		{ { "baduser", 0 }, { "worseuser", 8 } },
	    },
	},

	{ "3\n2\na 1\nb 2\nc 4\nd 8\ne 16\n", 0,
	    { 3, 2,
		{ { "a", 1 }, { "b", 2 }, { "c", 4 } },
		{ { "d", 8 }, { "e", 16 } },
	    },
	},
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	struct aclu_Acl *acl = NULL;

	is_int(aclu_ParseAcl(tc->str, &acl), tc->code,
	       "[%d] aclu_ParseAcl() == %d",
	       tc_i, tc->code);
	if (tc->code == 0) {
	    is_acl(acl, &tc->acl, "... acl matches");
	}
	aclu_FreeAcl(&acl);
    }
}

static void
test_ParseEmptyAcl(void)
{
    int tc_i;
    struct {
	const char *str;
	int code;

    } *tc, test_cases[] = {
	{ "2\n0\nsystem:administrators 127\nreaders 9\n" },
	{ "1\n1\nsystem:administrators 127\nbadusers 9\n" },
	{ "garbage" },
	{ "" },
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	struct aclu_Acl *acl = NULL;

	is_int(aclu_ParseEmptyAcl(tc->str, &acl), tc->code,
	       "[%d] aclu_ParseEmptyAcl() == %d",
	       tc_i, tc->code);
	if (tc->code == 0) {
	    is_int(acl->nplus, 0, "... nplus is 0");
	    is_pointer(acl->pluslist, NULL, "... pluslist is NULL");
	    is_int(acl->nminus, 0, "... nminus is 0");
	    is_pointer(acl->minuslist, NULL, "... minuslist is NULL");

	    is_int(acl->dfs, 0, "... dfs is 0");
	    is_string(acl->cell, "", "... cell is blank");
	}
    }
}

static void
test_AclToNetstring(void)
{
    int tc_i;

    struct aclu_AclEntry readers = { NULL, "readers", 9 };
    struct aclu_AclEntry pluslist_2 = { &readers, "system:administrators", 127 };

    struct aclu_AclEntry pluslist_1 = { NULL, "system:administrators", 127 };
    struct aclu_AclEntry minuslist_1 = { NULL, "baduser", 9 };

    struct {
	struct aclu_Acl acl;
	const char *netstr;

    } *tc, test_cases[] = {
	{
	    { 0, "", 2, 0, &pluslist_2, NULL },
	    "2\n0\nsystem:administrators 127\nreaders 9\n",
	},
	{
	    { 0, "", 1, 1, &pluslist_1, &minuslist_1 },
	    "1\n1\nsystem:administrators 127\nbaduser 9\n",
	},
	{
	    { 0, "", 0, 0, NULL, NULL },
	    "0\n0\n",
	},
	{
	    { 0, "", 0, 1, NULL, &minuslist_1 },
	    "0\n1\nbaduser 9\n",
	},
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	struct aclu_aclbuf buf;

	memset(&buf, 0, sizeof(buf));

	is_string(aclu_AclToNetstring(&tc->acl, &buf), tc->netstr,
		  "[%d] aclu_AclToNetstring() matches", tc_i);
    }
}

static int
TestFilterBadName(struct aclu_Acl *acl, int neg, char *name,
		  afs_uint32 rights, void *rock, int *a_remove)
{
    int *a_changed = rock;
    char *nm, tc;

    for (nm = name; (tc = *nm); nm++) {
	/* all must be '-' or digit to be bad */
	if (tc != '-' && (tc < '0' || tc > '9'))
	    return 0;
    }

    /* Assume all numerical names are bad */
    *a_remove = 1;
    *a_changed += 1;

    return 0;
}

static void
test_CleanAcl(void)
{
    int tc_i;

    struct {
	const char *acl;
	int code;
	int n_changes;
	const char *result;

    } *tc, test_cases[] = {
	{
	    "2\n0\nnsystem:administrators 127\nreaders 9\n",
	    0, 0,
	    "2\n0\nnsystem:administrators 127\nreaders 9\n",
	},
	{
	    "2\n0\nnsystem:administrators 127\n1234 9\n",
	    0, 1,
	    "1\n0\nnsystem:administrators 127\n",
	},
	{
	    "2\n0\nnsystem:administrators 127\n-1234 9\n",
	    0, 1,
	    "1\n0\nnsystem:administrators 127\n",
	},
	{
	    "2\n0\n567890 127\n-1234 9\n",
	    0, 2,
	    "0\n0\n",
	},
	{
	    "0\n2\nnsystem:administrators 127\nreaders 9\n",
	    0, 0,
	    "0\n2\nnsystem:administrators 127\nreaders 9\n",
	},
	{
	    "0\n2\nnsystem:administrators 127\n1234 9\n",
	    0, 1,
	    "0\n1\nnsystem:administrators 127\n",
	},
	{
	    "0\n2\nnsystem:administrators 127\n-1234 9\n",
	    0, 1,
	    "0\n1\nnsystem:administrators 127\n",
	},
	{
	    "0\n2\n567890 127\n-1234 9\n",
	    0, 2,
	    "0\n0\n",
	},
    };

    for (afstest_Scan(test_cases, tc, tc_i)) {
	struct aclu_Acl *acl;
	struct aclu_aclbuf buf;
	int changed = 0;
	int code;

	memset(&acl, 0, sizeof(acl));
	memset(&buf, 0, sizeof(buf));

	code = aclu_ParseAcl(tc->acl, &acl);
	opr_Assert(code == 0);

	code = aclu_FilterAcl(acl, TestFilterBadName, &changed);
	is_int(code, tc->code,
	       "[%d] aclu_FilterAcl() == %d",
	       tc_i, tc->code);

	is_int(changed, tc->n_changes,
	       "... changed == %d", tc->n_changes);

	is_string(aclu_AclToNetstring(acl, &buf), tc->result,
		  "... filtered acl matches");

	aclu_FreeAcl(&acl);
    }
}

int
main(void)
{
    plan(120);

    test_ParseRights();
    test_StringifyRights();
    test_ParseAcl();
    test_ParseEmptyAcl();
    test_AclToNetstring();
    test_CleanAcl();
}
