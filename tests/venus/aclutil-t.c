#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/prs_fs.h>
#include <tests/tap/basic.h>
#include <afs/acl.h>

static void
test_ParseRights(void)
{
    int code, offset = -1;
    enum rtype rtype;
    afs_int32 rights = 0;

    /* Simple letter combinations */
    code = acl_ParseRights("rl", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"rl\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    code = acl_ParseRights("rlia", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"rlia\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_ADMINISTER, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    code = acl_ParseRights("rABG", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"rABG\"");
    is_int(PRSFS_READ | PRSFS_USR0 | PRSFS_USR1 | PRSFS_USR6, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    /* AFS shorthands */
    code = acl_ParseRights("read", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"read\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    code = acl_ParseRights("mail", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"mail\"");
    is_int(PRSFS_INSERT | PRSFS_LOCK | PRSFS_LOOKUP, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    code = acl_ParseRights("write", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"write\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
	   PRSFS_WRITE | PRSFS_LOCK, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    code = acl_ParseRights("all", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"all\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
	   PRSFS_WRITE | PRSFS_LOCK | PRSFS_ADMINISTER, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct default rtype add");

    /* Modifiers */
    code = acl_ParseRights("rl-", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"rl-\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP, rights,
	   "... and produces correct rights bitmask");
    is_int(reldel, rtype, "... with correct rtype reldel");

    code = acl_ParseRights("read+", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"read+\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP, rights,
	   "... and produces correct rights bitmask");
    is_int(reladd, rtype, "... with correct rtype reladd");

    code = acl_ParseRights("all=", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"all=\"");
    is_int(PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
	   PRSFS_WRITE | PRSFS_LOCK | PRSFS_ADMINISTER, rights,
	   "... and produces correct rights bitmask");
    is_int(add, rtype, "... with correct rtype add");

    /* Special cases, none and null */
    code = acl_ParseRights("none", 0, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"none\"");
    is_int(0, rights, "... and produces correct rights bitmask");
    is_int(destroy, rtype, "... with correct rtype destroy");

    code = acl_ParseRights("null", 1, &rtype, &rights, &offset);
    is_int(0, code, "ParseRights succeeds for \"null\"");
    is_int(0, rights, "... and produces correct rights bitmask");
    is_int(deny, rtype, "... with correct rtype deny");

    /* Error handling */
    offset = -1;
    code = acl_ParseRights("bogus", 0, NULL, &rights, &offset);
    is_int(EINVAL, code,
	   "ParseRights fails for NULL rtype pointer with EINVAL");

    code = acl_ParseRights("bogus", 0, &rtype, NULL, &offset);
    is_int(EINVAL, code,
	   "ParseRights fails for NULL output rights pointer with EINVAL");

    code = acl_ParseRights(NULL, 0, &rtype, &rights, &offset);
    is_int(EINVAL, code,
	   "ParseRights fails for NULL rights pointer with EINVAL");

    code = acl_ParseRights("rlbogus", 0, &rtype, &rights, &offset);
    is_int(EINVAL, code, "ParseRights fails for illegal character");
    is_int(2, offset, "... and produces the correct error offset");
    offset = -1;
}

static void
test_StringifyRights(void)
{
    struct acl_stringbuf buf;
    char *str;

    /* Simple rights combinations */
    str = acl_StringifyRights(PRSFS_READ | PRSFS_LOOKUP, 0, &buf);
    is_string("rl", str, "StringifyRights converts READ|LOOKUP to \"rl\"");

    str = acl_StringifyRights(PRSFS_READ | PRSFS_WRITE | PRSFS_ADMINISTER,
			      0, &buf);
    is_string("rwa", str,
	      "StringifyRights converts READ|WRITE|ADMINISTER to \"rwa\"");

    str = acl_StringifyRights(PRSFS_READ | PRSFS_USR0 | PRSFS_USR3,
			      0, &buf);
    is_string("rAD", str, "StringifyRights converts READ|USR0|USR3 to \"rAD\"");

    /* No rights and full rights */
    str = acl_StringifyRights(0, 0, &buf);
    is_string("", str, "StringifyRights converts no rights to empty string");

    str = acl_StringifyRights(PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT |
			      PRSFS_DELETE | PRSFS_WRITE | PRSFS_LOCK |
			      PRSFS_ADMINISTER, 0, &buf);
    is_string("rlidwka", str,
	      "StringifyRights converts all rights to \"rlidwka\"");

    /* Error handling */
    str = acl_StringifyRights(PRSFS_READ, 0, NULL);
    is_string("(null)", str, "StringifyRights outputs (null) for NULL buffer");
}

static struct AclEntry *
findentry(struct AclEntry *list, const char *name)
{
    while (list != NULL) {
	if (strcmp(list->name, name) == 0) {
	    return list;
	}
	list = list->next;
    }
    return NULL;
}

int
listlength(struct AclEntry *list)
{
    int n = 0;
    while (list != NULL) {
	n++;
	list = list->next;
    }
    return n;
}

static void
test_ParseAcl(void)
{
    int code;
    struct Acl *acl;
    struct AclEntry *entry;
    char astr[AFS_PIOCTL_MAXSIZE + 24];

    /* Simple AFS ACL string */
    snprintf(astr, sizeof(astr),
	     "2\n"
	     "1\n"
	     "system:administrators %d\n"
	     "tester %d\n"
	     "hacker %d\n",
	     PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	     PRSFS_READ | PRSFS_LOOKUP,
	     PRSFS_INSERT | PRSFS_LOCK);
    code = acl_ParseAcl(astr, &acl);

    is_int(0, code, "ParseAcl successfully parses simple AFS ACL string");
    is_int(2, acl->nplus, "... and parses nplus correctly");
    is_int(1, acl->nminus, "... and parses nminus correctly");
    is_int(0, acl->dfs, "... and parses dfs status correctly");

    is_int(2, listlength(acl->pluslist),
	   "... and has the correct pluslist length");
    is_int(1, listlength(acl->minuslist),
	   "... and has the correct minuslist length");

    entry = findentry(acl->pluslist, "system:administrators");
    ok(entry != NULL, "... and pluslist contains system:administrators");
    if (entry != NULL) {
	is_int(PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	       entry->rights, "... and has the correct rights");
    }

    entry = findentry(acl->pluslist, "tester");
    ok(entry != NULL, "... and pluslist contains tester");
    if (entry != NULL) {
	is_int(PRSFS_READ | PRSFS_LOOKUP, entry->rights,
	       "... and has the correct rights");
    }

    entry = findentry(acl->minuslist, "hacker");
    ok(entry != NULL, "... and minuslist contains hacker");
    if (entry != NULL) {
	is_int(PRSFS_INSERT | PRSFS_LOCK, entry->rights,
	       "... and has the correct rights");
    }
    acl_ZapAcl(&acl);

    /* Empty ACL string */
    code = acl_ParseAcl("0\n0\n", &acl);
    is_int(0, code, "ParseAcl successfully parses an empty ACL");
    is_int(0, acl->nplus, "... and parses nplus correctly");
    is_int(0, acl->nminus, "... and parses nminus correctly");
    is_int(0, acl->dfs, "... and parses dfs status correctly");

    is_int(0, listlength(acl->pluslist),
	   "... and has the correct pluslist length");
    is_int(0, listlength(acl->minuslist),
	   "... and has the correct minuslist length");
    acl_ZapAcl(&acl);

    /* Error handling */
    code = acl_ParseAcl(NULL, &acl);
    is_int(EINVAL, code, "ParseAcl returns EINVAL for NULL ACL strings");

    code = acl_ParseAcl(astr, NULL);
    is_int(EINVAL, code, "ParseAcl returns EINVAL for NULL ACL struct pointer");

    code = acl_ParseAcl("\n\n", &acl);
    is_int(EINVAL, code,
	   "ParseAcl returns EINVAL for malformed ACL string header");

    code = acl_ParseAcl("1\n0\ntester", &acl);
    is_int(EINVAL, code,
	   "ParseAcl returns EINVAL for malformed ACL string body");

    code = acl_ParseAcl("2\n0\ntester", &acl);
    is_int(EINVAL, code,
	   "ParseAcl returns EINVAL for mismatch in nplus and positive list");

    code = acl_ParseAcl("0\n2\ntester", &acl);
    is_int(EINVAL, code,
	   "ParseAcl returns EINVAL for mismatch in nminus and negative list");
}

static void
test_ZapAcl(void)
{
    int code;
    struct Acl *acl;

    char astr[AFS_PIOCTL_MAXSIZE + 24];

    /* Simple AFS ACL string */
    snprintf(astr, sizeof(astr),
	     "2\n"
	     "1\n"
	     "system:administrators %d\n"
	     "tester %d\n"
	     "hacker %d\n",
	     PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	     PRSFS_READ | PRSFS_LOOKUP,
	     PRSFS_INSERT | PRSFS_LOCK);
    code = acl_ParseAcl(astr, &acl);

    is_int(0, code, "ParseAcl successfully parses simple ACL string");
    acl_ZapAcl(&acl);
    ok(acl == NULL, "... and ZapAcl successfully NULLs the caller pointer");
    acl_ZapAcl(&acl);
    ok(1, "... and calling ZapAcl twice is safe");

    acl_ZapAcl(NULL);
    ok(1, "Calling ZapAcl on NULL pointer is safe");
}

static void
test_EmptyAcl(void)
{
    int code;
    struct Acl *empty;

    /* Create with simple ACL string header as input */
    code = acl_EmptyAcl("2\n0\n", &empty);
    is_int(0, code, "EmptyAcl successfully creates Acl struct");
    is_int(0, empty->nplus, "... and sets nplus to 0, ignoring input nplus");
    ok(empty->pluslist == NULL, "... with an empty pluslist");
    is_int(0, empty->nminus, "... and sets nminus to 0");
    ok(empty->minuslist == NULL, "... with an empty minuslist");
    is_int(0, empty->dfs, "... and parses dfs status correctly");
    acl_ZapAcl(&empty);

    /* Create with simple DCE/DFS ACL string header as input */
    code = acl_EmptyAcl("0 dfs:1 example.com\n2\n", &empty);
    is_int(0, code, "EmptyAcl successfully creates DCE/DFS Acl struct");
    is_int(0, empty->nplus, "... and sets nplus to 0");
    ok(empty->pluslist == NULL, "... with an empty pluslist");
    is_int(0, empty->nminus, "... and sets nminus to 0");
    ok(empty->minuslist == NULL,
       "... with an empty minuslist, ignoring input nminus");
    is_int(1, empty->dfs, "... and parses dfs status correctly");
    is_string("example.com", empty->cell, "... and parses the cell correctly");
    acl_ZapAcl(&empty);

    /* Error handling */
    code = acl_EmptyAcl(NULL, &empty);
    is_int(EINVAL, code, "EmptyAcl returns EINVAL for NULL input");

    code = acl_EmptyAcl("2\n0\n", NULL);
    is_int(EINVAL, code, "EmptyAcl returns EINVAL for NULL Acl struct pointer");

    code = acl_EmptyAcl("abc\ndef\n", &empty);
    is_int(EINVAL, code,
	   "EmptyAcl returns EINVAL for malformed ACL string header");
}

static void
test_FindList(void)
{
    int code;
    struct Acl *acl;
    struct AclEntry *entry;

    char astr[AFS_PIOCTL_MAXSIZE + 24];

    /* Simple AFS ACL string */
    snprintf(astr, sizeof(astr),
	     "2\n"
	     "1\n"
	     "system:administrators %d\n"
	     "tester %d\n"
	     "hacker %d\n",
	     PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	     PRSFS_READ | PRSFS_LOOKUP,
	     PRSFS_INSERT | PRSFS_LOCK);

    code = acl_ParseAcl(astr, &acl);

    is_int(0, code, "ParseAcl successfully parses simple ACL string");

    entry = acl_FindList(acl->pluslist, "system:administrators");
    ok(entry != NULL,
       "... and FindList successfully finds an entry on the pluslist");
    if (entry != NULL) {
	is_string("system:administrators", entry->name,
		  "... with the correct name");
    }

    entry = acl_FindList(acl->minuslist, "hacker");
    ok(entry != NULL,
       "... and FindList successfully finds an entry on the minuslist");
    if (entry != NULL) {
	is_string("hacker", entry->name, "... with the correct name");
    }

    entry = acl_FindList(acl->pluslist, "TESTER");
    ok(entry != NULL,
       "... and FindList successfully finds an entry with different case");
    if (entry != NULL) {
	is_string("tester", entry->name, "... with the correct name");
    }

    /* Nonexistent name */
    entry = acl_FindList(acl->pluslist, "bogus");
    ok(entry == NULL, "... and FindList returns NULL for nonexistent name");
    acl_ZapAcl(&acl);

    /* Error handling */
    entry = acl_FindList(NULL, "bogus");
    ok(entry == NULL, "FindList returns NULL for NULL list");
}

static void
test_AclToString(void)
{
    int code;
    struct Acl *acl;

    char astr[AFS_PIOCTL_MAXSIZE + 24];
    char buf[AFS_PIOCTL_MAXSIZE + 24];

    /* Empty AFS ACL string */
    code = acl_ParseAcl("0\n0\n", &acl);
    is_int(0, code, "ParseAcl successfully parses empty ACL string");

    code = acl_AclToString(acl, buf, sizeof(buf));
    is_int(0, code,
	   "... and AclToString successfully converts it back to a string");
    is_string("0\n0\n", buf, "... as the correct, initial string");
    acl_ZapAcl(&acl);

    /* Simple AFS ACL string */
    snprintf(astr, sizeof(astr),
	     "2\n"
	     "1\n"
	     "system:administrators %d\n"
	     "tester %d\n"
	     "hacker %d\n",
	     PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	     PRSFS_READ | PRSFS_LOOKUP,
	     PRSFS_INSERT | PRSFS_LOCK);

    code = acl_ParseAcl(astr, &acl);

    is_int(0, code, "ParseAcl successfully parses simple ACL string");

    code = acl_AclToString(acl, buf, sizeof(buf));
    is_int(0, code,
	   "... and AclToString successfully converts it back to a string");
    is_string(astr, buf, "... as the correct, initial string");

    /* Error handling */
    code = acl_AclToString(acl, buf, 0);
    is_int(ENOSPC, code, "AclToString returns ENOSPC with len too small");

    code = acl_AclToString(NULL, buf, sizeof(buf));
    is_int(EINVAL, code, "AclToString returns EINVAL with NULL Acl struct");

    code = acl_AclToString(acl, NULL, sizeof(buf));
    is_int(EINVAL, code, "AclToString returns EINVAL with NULL buffer");
    acl_ZapAcl(&acl);
}

static void
test_ChangeList(void)
{
    enum rtype rtype;
    struct AclEntry *entry;
    struct Acl *acl;
    int code;
    char astr[AFS_PIOCTL_MAXSIZE + 24];
    char longname[MAXNAME + 10];

    /* Simple AFS ACL string */
    snprintf(astr, sizeof(astr),
	     "2\n"
	     "1\n"
	     "system:administrators %d\n"
	     "tester %d\n"
	     "hacker %d\n",
	     PRSFS_READ | PRSFS_WRITE | PRSFS_DELETE | PRSFS_ADMINISTER,
	     PRSFS_READ | PRSFS_LOOKUP,
	     PRSFS_INSERT | PRSFS_LOCK);

    code = acl_ParseAcl(astr, &acl);

    is_int(0, code, "ParseAcl successfully parses simple ACL string");

    /* Add a new entry */
    code = acl_ChangeList(acl, 1, "newuser",
			  PRSFS_READ | PRSFS_LOOKUP | PRSFS_DELETE, NULL);
    is_int(0, code, "ChangeList adds a new entry");
    entry = acl_FindList(acl->pluslist, "newuser");
    ok(entry != NULL, "... and the entry is present in the pluslist");
    if (entry != NULL) {
	is_int(PRSFS_READ | PRSFS_LOOKUP | PRSFS_DELETE, entry->rights,
	       "... and has the correct rights");
    }
    is_int(3, acl->nplus, "... and nplus is correctly incremented");
    is_int(3, listlength(acl->pluslist),
	   "... and the pluslist length is correct");

    /* Modifying existing (default, e.g. rtype add) */
    code = acl_ChangeList(acl, 1, "tester", PRSFS_READ, NULL);
    is_int(0, code, "ChangeList modifies an existing entry with default rtype");
    entry = acl_FindList(acl->pluslist, "tester");
    ok(entry != NULL, "... and the entry is present in the pluslist");
    if (entry != NULL) {
	is_int(PRSFS_READ, entry->rights, "... and has the correct rights");
    }

    /* Modifying existing (rtype reladd) */
    rtype = reladd;
    code = acl_ChangeList(acl, 1, "tester", PRSFS_LOOKUP, &rtype);
    is_int(0, code, "ChangeList modifies an existing entry with reladd rtype");
    entry = acl_FindList(acl->pluslist, "tester");
    ok(entry != NULL, "... and the entry is present in the pluslist");
    if (entry != NULL) {
	is_int(PRSFS_READ | PRSFS_LOOKUP, entry->rights,
	       "... and has the correct rights");
    }

    /* Modifying existing (rtype reldel) */
    rtype = reldel;
    code = acl_ChangeList(acl, 1, "tester", PRSFS_LOOKUP | PRSFS_ADMINISTER,
			  &rtype);
    is_int(0, code, "ChangeList modifies an existing entry with reldel rtype");
    entry = acl_FindList(acl->pluslist, "tester");
    ok(entry != NULL, "... and the entry is present in the pluslist");
    if (entry != NULL) {
	is_int(PRSFS_READ, entry->rights, "... and has the correct rights");
    }

    /* Deleting entry by removing all rights with rtype reldel */
    rtype = reldel;
    code = acl_ChangeList(acl, 1, "tester", PRSFS_READ, &rtype);
    is_int(0, code, "ChangeList removes an existing entry with reldel rtype");
    entry = acl_FindList(acl->pluslist, "tester");
    ok(entry == NULL, "... and the entry is not present in the pluslist");
    is_int(2, acl->nplus, "... and nplus was decremented");
    is_int(2, listlength(acl->pluslist),
	   "... and the pluslist length is decremented");

    /* Deleting entry by setting rights to 0 with add */
    code = acl_ChangeList(acl, 1, "newuser", 0, NULL);
    is_int(0, code, "ChangeList removes an existing entry with default rtype");
    entry = acl_FindList(acl->pluslist, "tester");
    ok(entry == NULL, "... and the entry is not present in the pluslist");
    is_int(1, acl->nplus, "... and nplus was decremented");
    is_int(1, listlength(acl->pluslist),
	   "... and the pluslist length is decremented");

    /* Attempting to modify nonexistent entry with reldel (no op) */
    rtype = reldel;
    code = acl_ChangeList(acl, 1, "bogus", PRSFS_READ, &rtype);
    is_int(0, code,
	   "ChangeList attempts to modify nonexistent entry with reldel rtype");
    entry = acl_FindList(acl->pluslist, "bogus");
    ok(entry == NULL, "... and the entry is not present in the pluslist");
    entry = acl_FindList(acl->minuslist, "bogus");
    ok(entry == NULL, "... and the entry is not present in the minuslist");
    is_int(1, acl->nplus, "... and nplus is the same");
    is_int(1, listlength(acl->pluslist),
	   "... and the pluslist length is the same");
    is_int(1, acl->nminus, "... and nminus is the same");
    is_int(1, listlength(acl->minuslist),
	   "... and the minuslist length is the same");

    /* Modifying minuslist entry */
    code = acl_ChangeList(acl, 0, "hacker", PRSFS_READ, NULL);
    is_int(0, code, "ChangeList modifies an existing entry in the minuslist");
    entry = acl_FindList(acl->minuslist, "hacker");
    ok(entry != NULL, "... and the entry is present in the minuslist");
    if (entry != NULL) {
	is_int(PRSFS_READ, entry->rights, "... and has the correct rights");
    }

    /* Error handling */
    memset(longname, 'x', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    code = acl_ChangeList(acl, 1, longname, PRSFS_READ, NULL);
    is_int(EINVAL, code, "ChangeList returns EINVAL on overly long name");

    rtype = (enum rtype)(-1);
    code = acl_ChangeList(acl, 0, "hacker", PRSFS_READ, &rtype);
    is_int(EINVAL, code, "ChangeList returns EINVAL for invalid rtype");

    acl_ZapAcl(&acl);
}

int
main(int argc, char **argv)
{
    plan(144);

    test_ParseRights();
    test_StringifyRights();
    test_ParseAcl();
    test_ZapAcl();
    test_EmptyAcl();
    test_FindList();
    test_AclToString();
    test_ChangeList();

    return 0;
}