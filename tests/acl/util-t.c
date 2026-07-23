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

int
main(void)
{
    plan(50);

    test_ParseRights();
}
