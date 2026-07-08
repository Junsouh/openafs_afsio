/*
 * Copyright (c) 2007, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Revised in 2010 by Chaz Chandler to enhance clientless operations.
 * Now utilizes libafscp by Chaskiel Grundman.
 * Work funded in part by Sine Nomine Associates (http://www.sinenomine.net/)
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

#ifdef AFS_NT40_ENV
#include <windows.h>
#define _CRT_RAND_S
#include <afs/smb_iocons.h>
#include <afs/afsd.h>
#include <afs/cm_ioctl.h>
#include <afs/pioctl_nt.h>
#include <WINNT/syscfg.h>
#else
#include <afs/afsint.h>
#define FSINT_COMMON_XG 1
#include <afs/unified_afs.h>
#endif

#include <afs/opr.h>
#include <afs/cmd.h>
#include <afs/auth.h>
#include <afs/vlserver.h>
#include <afs/ihandle.h>
#include <afs/com_err.h>
#include <afs/afscp.h>
#include <afs/acl.h>
#include <afs/ptuser.h>
#include <afs/ptclient.h>

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#include <hcrypto/md5.h>
#ifdef AFS_PTHREAD_ENV
pthread_key_t uclient_key;
#endif

static int lockFile(struct cmd_syndesc *, void *);
static int readFile(struct cmd_syndesc *, void *);
static int writeFile(struct cmd_syndesc *, void *);
static int removeFile(struct cmd_syndesc *, void *);
static int listAcl(struct cmd_syndesc *, void *);
static int setAcl(struct cmd_syndesc *, void *);
static int listMount(struct cmd_syndesc *, void *);
static int makeMount(struct cmd_syndesc *, void *);
static void printDatarate(void);
static void summarizeDatarate(struct timeval *, const char *);
static int CmdProlog(struct cmd_syndesc *, char **, char **,
                     char **, char **);
static int ScanFid(char *, struct AFSFid *);
static afs_int32 GetVenusFidByFid(char *, char *, int, struct afscp_venusfid **);
static afs_int32 GetVenusFidByPath(char *, char *, struct afscp_venusfid **);
static int BreakUpPath(char *, char **, char **);

static char pnp[AFSPATHMAX];	/* filename of this program when called */
static int verbose = 0;		/* Set if -verbose option given */
static int clear = 0;		/* Set if -clear option given,
				   Unset if -crypt given; default is -crypt */
static int force = 0;		/* Set if -force option given */
static int readlock = 0;	/* Set if -readlock option given */
static int waitseconds = 0;	/* Set if -waitseconds option given */
static int useFid = 0;		/* Set if fidwrite/fidread/fidappend invoked */
static int append = 0;		/* Set if append/fidappend invoked */
static int readDir = 0;		/* Set if readdir/fidreaddir invoked. */
static struct timeval starttime, opentime, readtime, writetime;
static afs_uint64 xfered = 0;
static struct timeval now;
#ifdef AFS_NT40_ENV
static int Timezone;            /* Roken gettimeofday ignores the timezone */
#else
static struct timezone Timezone;
#endif

#define MOUNTSTR_MAX 1024
#define BUFFLEN 65536
#define WRITEBUFLEN (BUFFLEN * 1024)
#define MEGABYTE_F 1048576.0f

static MD5_CTX md5;
static int md5sum = 0;		/* Set if -md5 option given */

struct wbuf {
    struct wbuf *next;
    afs_uint32 offset;		/* offset inside the buffer */
    afs_uint32 buflen;		/* total length == BUFFLEN */
    afs_uint32 used;		/* bytes used inside buffer */
    char buf[BUFFLEN];
};

/*
 * Constants for common_parms() global parameters. Start at offset 16, to try
 * to avoid conflicting with any subcommand-specific parameters. If any
 * subcommand uses more than 16 params, these constants will need to change.
 */
enum {
    OPT_cell	    = 16,
    OPT_realm	    = 17,
    OPT_clear	    = 18,
    OPT_crypt	    = 19,
    OPT_asuser	    = 20,
    OPT_verbose	    = 21,
};

/*!
 *  returns difference in seconds between two times
 *
 *  \param[in]	from	start time
 *  \param[in]	to	end time
 *
 *  \post returns "to" minus "from" in seconds
 *
 */
static_inline float
time_elapsed(struct timeval *from, struct timeval *to)
{
    return (float)(to->tv_sec + (to->tv_usec * 0.000001) - from->tv_sec -
		   (from->tv_usec * 0.000001));
} /* time_elapsed */

/*!
 * prints current average data transfer rate at no less than 30-second intervals
 */
static void
printDatarate(void)
{
    static float oldseconds = 0.0;
    static afs_uint64 oldxfered = 0;
    float seconds;

    gettimeofday(&now, &Timezone);
    seconds = time_elapsed(&opentime, &now);
    if ((seconds - oldseconds) > 30) {
	fprintf(stderr, "%llu MB transferred, present data rate = %.3f MB/sec.\n", xfered >> 20,	/* total bytes transferred, in MB */
		(xfered - oldxfered) / (seconds - oldseconds) / MEGABYTE_F);
	oldxfered = xfered;
	oldseconds = seconds;
    }
} /* printDatarate */

/*!
 * prints overall average data transfer rate and elapsed time
 *
 * \param[in]	tvp		current time (to compare with file open time)
 * \param[in]	xfer_type	string identify transfer type ("read" or "write")
 */
static void
summarizeDatarate(struct timeval *tvp, const char *xfer_type)
{
    float seconds = time_elapsed(&opentime, tvp);

    fprintf(stderr, "Transfer of %llu bytes took %.3f sec.\n",
	    xfered, seconds);
    fprintf(stderr, "Total data rate = %.03f MB/sec. for %s\n",
	    xfered / seconds / MEGABYTE_F, xfer_type);
} /* summarizeDatarate */

/*!
 * prints final MD5 sum of all file data transferred
 *
 * \param[in]	fname	file name or FID
 */
static void
summarizeMD5(char *fname)
{
    afs_uint32 md5int[4];
    char *p;

    MD5_Final((char *) &md5int[0], &md5);
    p = fname + strlen(fname);
    while (p > fname) {
	if (*(--p) == '/') {
	    ++p;
	    break;
	}
    }
    fprintf(stderr, "%08x%08x%08x%08x  %s\n", htonl(md5int[0]),
	    htonl(md5int[1]), htonl(md5int[2]), htonl(md5int[3]), p);
} /* summarizeMD5 */

#ifdef AFS_NT40_ENV
static void
ConvertAFSPath(char **fnp)
{
    char *p;

    for (p = *fnp; *p; p++) {
        if (*p == '\\')
           *p = '/';
    }

    p = *fnp;
    if (p[0] == '/' && p[1] == '/')
        *fnp = p+1;
}
#endif /* AFS_NT40_ENV */

/*!
 * parses all command-line arguments
 *
 * \param[in]  as	arguments list
 * \param[out] cellp	cell name
 * \param[out] realmp	realm name
 * \param[out] fnp	filename (either fid or path)
 * \param[out] slp	"synthesized" (made up) data given
 *
 * \post returns 0 on success or -1 on error
 *
 */
static int
CmdProlog(struct cmd_syndesc *as, char **cellp, char **realmp,
          char **fnp, char **slp)
{
    int i;
    int code;
    struct cmd_parmdesc *pdp;

    if (as == NULL) {
	afs_com_err(pnp, EINVAL, "(syndesc is null)");
	return -1;
    }

    /* determine which command was requested */
    if (strncmp(as->name, "fid", 3) == 0) /* fidread/fidwrite/fidappend */
	useFid = 1;
    if ( (strcmp(as->name, "append") == 0) ||
         (strcmp(as->name, "fidappend") == 0) )
	append = 1;		/* global */
    if (strcmp(as->name, "readdir") == 0 ||
        strcmp(as->name, "fidreaddir") == 0)
        readDir = 1;

    /* attempts to ensure loop is bounded: */
    for (pdp = as->parms, i = 0; pdp && (i < as->nParms); i++, pdp++) {
	if (pdp->items != NULL) {
	    if (strcmp(pdp->name, "-verbose") == 0)
	        verbose = 1;
	    if (strcmp(pdp->name, "-clear") == 0)
	        clear = 1;
	    if (strcmp(pdp->name, "-crypt") == 0)
	        clear = 0;
            else if (strcmp(pdp->name, "-md5") == 0)
		md5sum = 1;	/* global */
            else if (strcmp(pdp->name, "-cell") == 0) {
		*cellp = pdp->items->data;
            } else if ( strcmp(pdp->name, "-file") == 0 ||
			strcmp(pdp->name, "-dir") == 0) {
		*fnp = pdp->items->data;
#ifdef AFS_NT40_ENV
                ConvertAFSPath(fnp);
#endif /* AFS_NT40_ENV */
            } else if ( (strcmp(pdp->name, "-fid") == 0) ||
                        (strcmp(pdp->name, "-vnode") == 0) ) {
		*fnp = pdp->items->data;
            } else if (strcmp(pdp->name, "-force") == 0)
		force = 1;	/* global */
            else if (strcmp(pdp->name, "-synthesize") == 0)
		*slp = pdp->items->data;
            else if (strcmp(pdp->name, "-realm") == 0)
		*realmp = pdp->items->data;
	    else if (strcmp(pdp->name, "-waitseconds") == 0)
		waitseconds = atoi(pdp->items->data);
            else if (strcmp(pdp->name, "-readlock") == 0)
		readlock = 1;
	    else if (strcmp(pdp->name, "-as-user") == 0) {
		code = afscp_LocalAuthAs(pdp->items->data);
		if (code != 0) {
		    afs_com_err(pnp, code, "error setting -as-user '%s'",
				pdp->items->data);
		    return -1;
		}
	    }
	}
    }
    return 0;
}				/* CmdProlog */

static void
common_parms(struct cmd_syndesc *as)
{
    cmd_AddParmAtOffset(as, OPT_cell, "-cell", CMD_SINGLE, CMD_OPTIONAL,
			"cellname");
    cmd_AddParmAtOffset(as, OPT_realm, "-realm", CMD_SINGLE, CMD_OPTIONAL,
			"realmname");
    cmd_AddParmAtOffset(as, OPT_clear, "-clear", CMD_FLAG, CMD_OPTIONAL,
			"use an unencrypted connection");
    cmd_AddParmAtOffset(as, OPT_crypt, "-crypt", CMD_FLAG, CMD_OPTIONAL,
			"use an encrypted connection");
    cmd_AddParmAtOffset(as, OPT_asuser, "-as-user", CMD_SINGLE, CMD_OPTIONAL,
			"username");
    cmd_AddParmAtOffset(as, OPT_verbose, "-verbose", CMD_FLAG, CMD_OPTIONAL,
			"enable verbose output");
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *ts;
    char *baseName;
    int code;

    /* try to get only the base name of this executable for use in logs */
#ifdef AFS_NT40_ENV
    char *p = strdup(argv[0]);
    ConvertAFSPath(&p);
    code = BreakUpPath(p, NULL, &baseName);
    free(p);
#else
    code = BreakUpPath(argv[0], NULL, &baseName);
#endif
    if (code > 0)
	strlcpy(pnp, baseName, AFSNAMEMAX);
    else
	strlcpy(pnp, argv[0], AFSPATHMAX);
    free(baseName);

#ifndef AFS_NT40_ENV
    initialize_uae_error_table();
#endif

#ifdef AFS_PTHREAD_ENV
    opr_Verify(pthread_key_create(&uclient_key, NULL) == 0);
#endif

    ts = cmd_CreateSyntax("lock", lockFile, (void *)LockWrite, 0,
			  "lock a file in AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    cmd_AddParm(ts, "-waitseconds", CMD_SINGLE, CMD_OPTIONAL, "seconds to wait before giving up");
    cmd_AddParm(ts, "-readlock", CMD_FLAG, CMD_OPTIONAL, "read lock only");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidlock", lockFile, (void *)LockWrite, 0,
			  "lock by FID a file from AFS");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_AddParm(ts, "-waitseconds", CMD_SINGLE, CMD_OPTIONAL, "seconds to wait before giving up");
    cmd_AddParm(ts, "-readlock", CMD_FLAG, CMD_OPTIONAL, "read lock only");
    common_parms(ts);

    ts = cmd_CreateSyntax("unlock", lockFile, (void *)LockRelease, 0,
			  "unlock a file in AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    cmd_AddParm(ts, "-waitseconds", CMD_SINGLE, CMD_OPTIONAL, "seconds to wait before giving up");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidunlock", lockFile, (void *)LockRelease, 0,
			  "unlock by FID a file from AFS");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_AddParm(ts, "-waitseconds", CMD_SINGLE, CMD_OPTIONAL, "seconds to wait before giving up");
    common_parms(ts);

    ts = cmd_CreateSyntax("read", readFile, NULL, 0,
			  "read a file from AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidread", readFile, CMD_REQUIRED, 0,
			  "read on a non AFS-client a file from AFS");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    common_parms(ts);

    ts = cmd_CreateSyntax("readdir", readFile, CMD_REQUIRED, 0,
			  "read a directory from AFS");
    cmd_AddParm(ts, "-dir", CMD_SINGLE, CMD_REQUIRED, "AFS-dirname");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidreaddir", readFile, CMD_REQUIRED, 0,
			  "read on a non AFS-client a directory from AFS");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    common_parms(ts);

    ts = cmd_CreateSyntax("write", writeFile, NULL, 0,
			  "write a file into AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL,
		"overwrite existing file");
    cmd_Seek(ts, 5);
    cmd_AddParm(ts, "-synthesize", CMD_SINGLE, CMD_OPTIONAL,
		"create data pattern of specified length instead reading from stdin");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidwrite", writeFile, CMD_REQUIRED, 0,
			  "write a file into AFS");
    cmd_AddParm(ts, "-vnode", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "calculate md5 checksum");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL,
		"overwrite existing file");
    cmd_Seek(ts, 5);
    cmd_AddParm(ts, "-synthesize", CMD_SINGLE, CMD_OPTIONAL,
		"create data pattern of specified length instead of reading from stdin");
    common_parms(ts);

    ts = cmd_CreateSyntax("append", writeFile, NULL, 0,
			  "append to a file in AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    cmd_Seek(ts, 5);
    cmd_AddParm(ts, "-synthesize", CMD_SINGLE, CMD_OPTIONAL,
		"create data pattern of specified length instead reading from stdin");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidappend", writeFile, NULL, 0,
			  "append to a file in AFS");
    cmd_AddParm(ts, "-vnode", CMD_SINGLE, CMD_REQUIRED,
		"volume.vnode.uniquifier");
    cmd_Seek(ts, 5);
    cmd_AddParm(ts, "-synthesize", CMD_SINGLE, CMD_OPTIONAL,
		"create data pattern of specified length instead reading from stdin");
    common_parms(ts);

    ts = cmd_CreateSyntax("rmfile", removeFile, NULL, 0,
			  "delete a file from AFS");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "AFS-filename");
    common_parms(ts);

    ts = cmd_CreateSyntax("listacl", listAcl, NULL, 0,
			  "list the ACL of a directory from AFS");
    cmd_AddParm(ts, "-dir", CMD_LIST, CMD_REQUIRED, "AFS-dirname");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidlistacl", listAcl, NULL, 0,
			  "list the ACL of a directory from AFS by FID");
    cmd_AddParm(ts, "-fid", CMD_LIST, CMD_REQUIRED,
		"volume.vnode.uniquifier");;
    common_parms(ts);

    ts = cmd_CreateSyntax("setacl", setAcl, NULL, 0,
			  "set the ACL of a directory from AFS");
    cmd_AddParm(ts, "-dir", CMD_LIST, CMD_REQUIRED, "AFS-dirname");
    cmd_AddParm(ts, "-acl", CMD_LIST, CMD_REQUIRED, "access list entries");
    cmd_AddParm(ts, "-clearacl", CMD_FLAG, CMD_OPTIONAL, "clear access list");
    cmd_AddParm(ts, "-negative", CMD_FLAG, CMD_OPTIONAL,
		"apply to negative rights");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidsetacl", setAcl, NULL, 0,
			  "set the ACL of a directory from AFS by FID");
    cmd_AddParm(ts, "-fid", CMD_LIST, CMD_REQUIRED, "volume.vnode.uniquifier");
    cmd_AddParm(ts, "-acl", CMD_LIST, CMD_REQUIRED, "access list entries");
    cmd_AddParm(ts, "-clearacl", CMD_FLAG, CMD_OPTIONAL, "clear access list");
    cmd_AddParm(ts, "-negative", CMD_FLAG, CMD_OPTIONAL,
		"apply to negative rights");
    common_parms(ts);

    ts = cmd_CreateSyntax("lsmount", listMount, NULL, 0,
			  "list the ACL of a directory from AFS");
    cmd_AddParm(ts, "-dir", CMD_LIST, CMD_REQUIRED, "AFS-dirname");
    common_parms(ts);

    ts = cmd_CreateSyntax("fidlsmount", listMount, NULL, 0,
			  "list the ACL of a directory from AFS");
    cmd_AddParm(ts, "-fid", CMD_LIST, CMD_REQUIRED,
		"volume.vnode.uniquifier");;
    common_parms(ts);

    ts = cmd_CreateSyntax("mkmount", makeMount, NULL, 0,
			  "make a mount point to a volume");
    cmd_AddParm(ts, "-dir", CMD_SINGLE, CMD_REQUIRED, "AFS-dirname");
    cmd_AddParm(ts, "-vol", CMD_SINGLE, CMD_REQUIRED, "volume name");
    cmd_AddParm(ts, "-mountcell", CMD_SINGLE, CMD_OPTIONAL,
		"cell name for foreign cell mount");
    cmd_AddParm(ts, "-rw", CMD_FLAG, CMD_OPTIONAL, "force r/w volume");
    cmd_AddParm(ts, "-fast", CMD_FLAG, CMD_OPTIONAL, "skip volume check");
    common_parms(ts);

    if (afscp_Init(NULL) != 0)
	exit(1);

    cmd_Dispatch(argc, argv);

    afscp_Finalize();
    exit(0);
} /* main */

/*!
 * standardized way of parsing a File ID (FID) from command line input
 *
 * \param[in]	fidString	dot-delimited FID triple
 * \param[out]	fid		pointer to the AFSFid to fill in
 *
 * \post The FID pointed to by "fid" is filled in which the parsed Volume,
 *       Vnode, and Uniquifier data.  The string should be in the format
 *       of three numbers separated by dot (.) delimiters, representing
 *       (in order) the volume id, vnode number, and uniquifier.
 *       Example: "576821346.1.1"
 */
static int
ScanFid(char *fidString, struct AFSFid *fid)
{
    int i = 0, code = 0;
    long unsigned int f1, f2, f3;

    if (fidString) {
	i = sscanf(fidString, "%lu.%lu.%lu", &f1, &f2, &f3);
	fid->Volume = (afs_uint32) f1;
	fid->Vnode = (afs_uint32) f2;
	fid->Unique = (afs_uint32) f3;
    }
    if (i != 3) {
	fid->Volume = 0;
	fid->Vnode = 0;
	fid->Unique = 0;
	code = EINVAL;
	afs_com_err(pnp, code, "(invalid FID triple: %s)", fidString);
    }

    return code;
} /* ScanFid */

/*!
 * look up cell info and verify FID info from user input
 *
 * \param[in]	fidString	string containing FID info
 * \param[in]	cellName	cell name string
 * \param[in]	onlyRW		bool: 1 = RW vol only, 0 = any vol type
 * \param[out]	avfpp		pointer to venusfid info
 *
 * \post *avfpp will contain the VenusFid info found for the FID
 *       given by the used in the string fidString and zero is
 *       returned.  If not found, an appropriate afs error code
 *       is returned and *avfpp will be NULL.
 *
 * \note Any non-NULL avfpp returned should later be freed with
 *       afscp_FreeFid() when no longer needed.
 */
static afs_int32
GetVenusFidByFid(char *fidString, char *cellName, int onlyRW,
                 struct afscp_venusfid **avfpp)
{
    afs_int32 code = 0;
    struct stat sbuf;
    struct afscp_volume *avolp;

    if (*avfpp == NULL) {
	*avfpp = calloc(1, sizeof(struct afscp_venusfid));
	if ( *avfpp == NULL ) {
	    code = ENOMEM;
	    return code;
	}
    }

    if (cellName == NULL) {
	(*avfpp)->cell = afscp_DefaultCell();
    } else {
	(*avfpp)->cell = afscp_CellByName(cellName, NULL);
    }
    if ((*avfpp)->cell == NULL) {
	if (afscp_errno == 0)
	    code = EINVAL;
	else
	    code = afscp_errno;
	return code;
    }

    code = ScanFid(fidString, &((*avfpp)->fid));
    if (code != 0) {
	code = EINVAL;
	return code;
    }

    avolp = afscp_VolumeById((*avfpp)->cell, (*avfpp)->fid.Volume);
    if (avolp == NULL) {
	if (afscp_errno == 0)
	    code = ENOENT;
	else
	    code = afscp_errno;
	afs_com_err(pnp, code, "(finding volume %lu)",
		    afs_printable_uint32_lu((*avfpp)->fid.Volume));
	return code;
    }

    if ( onlyRW && (avolp->voltype != RWVOL) ) {
	avolp = afscp_VolumeByName((*avfpp)->cell, avolp->name, RWVOL);
	if (avolp == NULL) {
	    if (afscp_errno == 0)
		code = ENOENT;
	    else
		code = afscp_errno;
	    afs_com_err(pnp, code, "(finding volume %lu)",
		        afs_printable_uint32_lu((*avfpp)->fid.Volume));
	    return code;
	}
	(*avfpp)->fid.Volume = avolp->id; /* is this safe? */
    }

    code = afscp_Stat((*avfpp), &sbuf);
    if (code != 0) {
	afs_com_err(pnp, afscp_errno, "(stat failed with errno %d)", afscp_errno);
	return code;
    }
    return 0;
} /* GetVenusFidByFid */

/*!
 * Split a full path up into dirName and baseName components
 *
 * \param[in]	fullPath	can be absolute, relative, or local
 * \param[out]	dirName		pointer to output string or NULL
 * \param[out]	baseName	pointer to output string or NULL
 *
 * \post A buffer of appropriate size will be allocated into the output
 *       parameter baseName and the rightmost full path component of the
 *       fullPath copied into it; likewise, the other components of the
 *       fullPath (minus the trailing path separator) will be placed into
 *       the dirName output, which is also allocated to be the appropriate
 *       size.  If either dirName or baseName are NULL, only the non-NULL
 *       pointer will be allocated and filled in (but both can't be null
 *       or it would be pointless) -- so the caller can retrieve, say,
 *       only baseName if desired.  The return code is the number of
 *       strings allocated and copied:
 *       0 if neither dirName nor baseName could be filled in
 *       1 if either dirName or baseName were filled in
 *       2 if both dirName and baseName were filled in
 */
static int
BreakUpPath(char *fullPath, char **dirName, char **baseName)
{
    char *lastSlash;
    size_t dirNameLen = 0;
    int code = 0, useDirName = 1, useBaseName = 1;

    if (fullPath == NULL) {
	return code;
    }

    /* Track what we need to output and initialize output variables to NULL. */
    if (dirName == NULL)
	useDirName = 0;
    else
	*dirName = NULL;
    if (baseName == NULL)
	useBaseName = 0;
    else
	*baseName = NULL;
    if (!useBaseName && !useDirName) {
	/* would be pointless to continue -- must be error in call */
	return code;
    }
    lastSlash = strrchr(fullPath, '/');
    if (lastSlash != NULL) {
	/* then lastSlash points to the last path separator in fullPath */
	if (useDirName) {
	    dirNameLen = strlen(fullPath) - strlen(lastSlash);
	    *dirName = strdup(fullPath);
	    if (*dirName != NULL) {
		code++;
		/* Wastes some memory, but avoids needing libroken. */
		(*dirName)[dirNameLen] = '\0';
	    }
	}
	if (useBaseName) {
	    lastSlash++;
	    *baseName = strdup(lastSlash);
	    if (*baseName != NULL)
		code++;
	}
    } else {
	/* there are no path separators in fullPath -- it's just a baseName */
	if (useBaseName) {
	    *baseName = strdup(fullPath);
	    if (*baseName != NULL)
		code++;
	}
    }
    return code;
} /* BreakUpPath */

/*!
 * Find the fid of the parent for a path.
 *
 * Given a path in afs, break the path into its base and parent, much like
 * BreakUpPath, and also find the fid for the parent. This function assumes that
 * if the path given is only a base, i.e. "test" and not "dir/test", the parent
 * is the cell root.
 *
 * \param[in]	path      file path
 * \param[out]	parentfid pointer to fid info to be filled in
 * \param[out]	basename  pointer to base string to be filled in
 * \param[out]	dirname   pointer to parent dir string to be filled in
 *
 * \return status code
 */

static int
GetParentFid(char *path, struct afscp_venusfid **parentfid, char **basename,
	     char **dirname)
{
    afs_int32 code = 0;

    if (parentfid == NULL || basename == NULL || path == NULL ||
	dirname == NULL) {
	code = EINVAL;
	return code;
    }
    *parentfid = NULL;
    *dirname = NULL;
    *basename = NULL;

    code = BreakUpPath(path, dirname, basename);
    if (code == 0) {
	code = EINVAL;
	return code;
    } else if (code == 1) {
	if (*basename == NULL) {
	    code = EINVAL;
	    return code;
	}
	*parentfid = afscp_ResolvePath(""); /* Get the cell root fid */
	if (*parentfid == NULL) {
	    code = afscp_errno != 0 ? afscp_errno : EINVAL;
	    return code;
	}
    } else {
	code = GetVenusFidByPath(*dirname, NULL, parentfid);
	if (code != 0) {
	    return code;
	}
    }

    return 0;
}

/*!
 * Get the VenusFid info available for the file at AFS path 'fullPath'.
 * Works without pioctls/afsd by using libafscp.  Analogous to
 * get_file_cell() in the previous iteration of afsio.
 *
 * \param[in]	fullPath	the file name
 * \param[in]	cellName	the cell name to look up
 * \param[out]	avfpp		pointer to Venus FID info to be filled in
 *
 * \post If the path resolves successfully (using afscp_ResolvePath),
 *       then vfpp will contain the Venus FID info (cell info plus
 *       AFSFid) of the last path segment in fullPath.
 */
static afs_int32
GetVenusFidByPath(char *fullPath, char *cellName,
                  struct afscp_venusfid **avfpp)
{
    afs_int32 code = 0;

    if (fullPath == NULL) {
	return -1;
    }

    if (cellName != NULL) {
	code = (afs_int32) afscp_SetDefaultCell(cellName);
	if (code != 0) {
	    return code;
	}
    }

    *avfpp = afscp_ResolvePath(fullPath);
    if (*avfpp == NULL) {
	if (afscp_errno == 0)
	    code = ENOENT;
	else
	    code = afscp_errno;
    }

    return code;
} /* GetVenusFidByPath */

/*!
 * Update the given parsed Acl struct with respect to the acl pairs given.
 *
 * @param[in]     aclpairs the acl pairs to update the Acl struct with
 * @param[in]     negative 0 if the positive list should be updated,
 *			   non-zero otherwise
 * @param[in,out] parsed   the Acl struct to update
 *
 * @return 0 on success, status code on error
 */
static int
UpdateAclEntries(struct cmd_item *aclpairs, int negative,
		 struct aclu_Acl *parsed)
{
    struct cmd_item *aclarg;
    afs_int32 code = 0;
    afs_uint32 rights;

    for (aclarg = aclpairs; aclarg != NULL;
	 aclarg = aclarg->next->next) {
	char badchar = 0;
	enum aclu_rights_type rtype;
	if (aclarg->next == NULL) {
	    code = EINVAL;
	    afs_com_err(pnp, code,
			"(missing second half of user/access pair)");
	    return code;
	}
	code = aclu_ParseRights(aclarg->next->data, &rights, &rtype, &badchar);
	if (code != 0) {
	    if (badchar != 0) {
		afs_com_err(pnp, code, "(illegal rights character '%c')",
			    badchar);
	    } else {
		afs_com_err(pnp, code, "(failed to parse ACL pair %s %s)",
			    aclarg->data, aclarg->next->data);
	    }
	    return code;
	}
	if (rtype == ACLU_RTYPE_DESTROY) {
	    struct aclu_AclEntry *tlist;

	    tlist = negative ? parsed->minuslist : parsed->pluslist;
	    if (aclu_SearchList(tlist, aclarg->data) == NULL) {
		continue;
	    }
	}
	code = aclu_UpdateList(parsed, !negative, aclarg->data, rights,
			       &rtype);
	if (code != 0) {
	    afs_com_err(pnp, code, "(failed to modify ACL list)");
	    return code;
	}
    }

    return 0;
}

struct cleanacl_data {
    char *cellname;
    int changed;
};

/*!
 * Check the given ACL entry to see if it is a vaid entry
 *
 * Entries that are comprised entirely of numbers and '-' characters may be
 * invalid entries, since that is the form they take once the user or group is
 * deleted from the pts database. This function checks a single entry to see
 * if it is valid.
 *
 * \param[in]	acl	 the aclu_Acl to check (unused)
 * \param[in]	neg	 nonzero for the negative list, 0 for the positive list
 *			 (unused)
 * \param[in]	aname	 name of the entry
 * \param[in]	rights	 rights mask of the entry (unused)
 * \param[out]	rock	 should be cast to struct cleanacl_data, contains number
 *			 of changes made and cellname
 * \param[out]	a_remove if the entry was removed or not
 *
 * \return error codes
 */
static int
FilterBadName(struct aclu_Acl *acl, int neg, char *aname,
	      afs_uint32 rights, void *rock, int *a_remove)
{
    struct cleanacl_data *data = rock;
    afs_int32 tc, code, id;
    char *nm;
    *a_remove = 0;

    for (nm = aname; (tc = *nm); nm++) {
	/* all must be '-' or digit to be bad */
	if (tc != '-' && (tc < '0' || tc > '9')) {
	    return 0;
	}
    }

    /* Go to the PRDB and see if this all number username is valid */
    code = pr_Initialize(1, AFSDIR_CLIENT_ETC_DIRPATH, data->cellname);
    if (code != 0) {
	return code;
    }

    code = pr_SNameToId(aname, &id);
    pr_End();

    if (code == 0 && id == ANONYMOUSID) {
	/* Not-valid */
	*a_remove = 1;
	data->changed++;
    }

    return 0;
}

/*!
 * Clean an ACL of its bad entries
 *
 * Uses FilterBadName() to clean, check that function for more details.
 *
 * \param[in]	aa	 the aclu_Acl to clean
 * \param[in]	cellname the cell to operate in
 *
 * \return number of changed entries
 */
static int
CleanAcl(struct aclu_Acl *aa, char *cellname)
{
    int code;
    struct cleanacl_data data;

    memset(&data, 0, sizeof(data));

    data.cellname = cellname;

    code = aclu_FilterAcl(aa, FilterBadName, &data);
    if (code != 0) {
	return 0;
    }

    return data.changed;
}

static int
lockFile(struct cmd_syndesc *as, void *arock)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 code = 0;
    struct AFSFetchStatus OutStatus;
    struct afscp_venusfid *avfp = NULL;
    char ipv4_addr[16];
    int locktype = (int)(intptr_t) arock;

#ifdef AFS_NT40_ENV
    /* stdout on Windows defaults to _O_TEXT mode */
    _setmode(1, _O_BINARY);
#endif

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear)
	afscp_Insecure();

    if ((locktype == LockWrite) && readlock)
	locktype = LockRead;

    if (realm != NULL)
	afscp_SetDefaultRealm(realm);

    if (cell != NULL)
	afscp_SetDefaultCell(cell);

    if (useFid)
	code = GetVenusFidByFid(fname, cell, 0, &avfp);
    else
	code = GetVenusFidByPath(fname, cell, &avfp);
    if (code != 0) {
	afs_com_err(pnp, code, "(file not found: %s)", fname);
	afscp_FreeFid(avfp);
	return code;
    }

retry:
    code = afscp_GetStatus(avfp, &OutStatus);
    if (code != 0) {
	afs_inet_ntoa_r(avfp->cell->fsservers[0]->addrs[0], ipv4_addr);
	afs_com_err(pnp, afscp_errno, "(failed to get status of file %s from"
		    "server %s, errno = %d)", fname, ipv4_addr, afscp_errno);
	afscp_FreeFid(avfp);
	return code;
    }

    if (locktype != LockRelease) {
	while (OutStatus.lockCount != 0) {
	    code = afscp_WaitForCallback(avfp, waitseconds);
	    if ((code == -1) && (afscp_errno == ETIMEDOUT))
		break;
	    if ((code = afscp_GetStatus(avfp, &OutStatus)) != 0)
		break;
	}
    } else {
	if (OutStatus.lockCount == 0) {
	    code = -1;
	}
    }

    if (!code) {
	code = afscp_Lock(avfp, locktype);
	if ((code == -1) && (afscp_errno == EWOULDBLOCK))
	    goto retry;
    }
    afscp_FreeFid(avfp);

    if (code != 0)
	afs_com_err(pnp, afscp_errno, "(failed to change lock status: %d)", afscp_errno);

    return code;
} /* lockFile */

static int
readFile(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 code = 0;
    struct AFSFetchStatus OutStatus;
    struct afscp_venusfid *avfp = NULL;
    afs_int64 Pos;
    afs_int32 len;
    afs_int64 length = 0, Len;
    int bytes;
    int worstCode = 0;
    char *buf = 0;
    char ipv4_addr[16];
    int bufflen = BUFFLEN;

#ifdef AFS_NT40_ENV
    /* stdout on Windows defaults to _O_TEXT mode */
    _setmode(1, _O_BINARY);
#endif

    gettimeofday(&starttime, &Timezone);

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear)
	afscp_Insecure();

    if (md5sum)
	MD5_Init(&md5);

    if (realm != NULL)
	afscp_SetDefaultRealm(realm);

    if (cell != NULL)
	afscp_SetDefaultCell(cell);

    if (useFid)
	code = GetVenusFidByFid(fname, cell, 0, &avfp);
    else
	code = GetVenusFidByPath(fname, cell, &avfp);
    if (code != 0) {
	afscp_FreeFid(avfp);
	afs_com_err(pnp, code, "(file not found: %s)", fname);
	return code;
    }

    if (readDir) {
	if ((avfp->fid.Vnode & 1) == 0) {
	    code = ENOENT;
	    afs_com_err(pnp, code, "(%s is a file, not a directory)", fname);
	    afscp_FreeFid(avfp);
	    return code;
	}
    } else if (avfp->fid.Vnode & 1) {
	code = ENOENT;
	afs_com_err(pnp, code, "(%s is a directory, not a file)", fname);
	afscp_FreeFid(avfp);
	return code;
    }

    code = afscp_GetStatus(avfp, &OutStatus);
    if (code != 0) {
	afs_inet_ntoa_r(avfp->cell->fsservers[0]->addrs[0], ipv4_addr);
	afs_com_err(pnp, afscp_errno, "(failed to get status of file %s from"
		    "server %s, errno = %d)", fname, ipv4_addr, afscp_errno);
	afscp_FreeFid(avfp);
	return code;
    }

    gettimeofday(&opentime, &Timezone);
    if (verbose)
	fprintf(stderr, "Startup to find the file took %.3f sec.\n",
		time_elapsed(&starttime, &opentime));
    Len = OutStatus.Length_hi;
    Len <<= 32;
    Len += OutStatus.Length;
    ZeroInt64(Pos);
    buf = calloc(bufflen, sizeof(char));
    if (buf == NULL) {
	code = ENOMEM;
	afs_com_err(pnp, code, "(cannot allocate buffer)");
	afscp_FreeFid(avfp);
	return code;
    }
    length = Len;
    while (!code && NonZeroInt64(length)) {
	if (length > bufflen)
	    len = bufflen;
	else
	    len = (afs_int32) length;
	bytes = afscp_PRead(avfp, buf, len, Pos);
	if (bytes != len)
	    code = -3; /* what error name should we use here? */
	if (md5sum)
	    MD5_Update(&md5, buf, len);
	if (code == 0) {
	    len = write(1, buf, len); /* to stdout */
	    if (len == 0)
		code = errno;
	}
	length -= len;
	xfered += len;
	if (verbose)
	    printDatarate();
	Pos += len;
	worstCode = code;
    }
    afscp_FreeFid(avfp);

    gettimeofday(&readtime, &Timezone);
    if (md5sum)
	summarizeMD5(fname);
    if (verbose)
	summarizeDatarate(&readtime, "read");
    if (buf != NULL)
	free(buf);

    return worstCode;
} /* readFile */

static int
writeFile(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *sSynthLen = NULL;
    char *realm = NULL;
    afs_int32 code = 0;
    afs_int32 byteswritten;
    struct AFSFetchStatus OutStatus;
    struct AFSStoreStatus InStatus;
    struct afscp_venusfid *dirvfp = NULL, *newvfp = NULL;
    afs_int64 Pos;
    afs_int64 length, Len, synthlength = 0, offset = 0;
    afs_int64 bytes;
    int synthesize = 0;
    int overWrite = 0;
    struct wbuf *bufchain = 0;
    struct wbuf *previous, *tbuf;
    char *dirName = NULL;
    char *baseName = NULL;
    char ipv4_addr[16];

#ifdef AFS_NT40_ENV
    /* stdin on Windows defaults to _O_TEXT mode */
    _setmode(0, _O_BINARY);
#endif
    memset(&InStatus, 0, sizeof(InStatus));

    if (CmdProlog(as, &cell, &realm, &fname, &sSynthLen) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear)
	afscp_Insecure();

    if (realm != NULL)
	afscp_SetDefaultRealm(realm);

    if (cell != NULL)
	afscp_SetDefaultCell(cell);

    if (sSynthLen) {
	code = util_GetInt64(sSynthLen, &synthlength);
	if (code != 0) {
	    afs_com_err(pnp, code, "(invalid value for synthesize length %s)",
			sSynthLen);
	    goto cleanup;
	}
	synthesize = 1;
    }

    if (useFid) {
	code = GetVenusFidByFid(fname, cell, 1, &newvfp);
	if (code != 0) {
	    afs_com_err(pnp, code, "(GetVenusFidByFid returned code %d)", code);
	    goto cleanup;
	}
    } else {
	code = GetVenusFidByPath(fname, cell, &newvfp);
	if (code == 0) { /* file was found */
	    if (force)
		overWrite = 1;
	    else if (!append) {
		/*
		 * file cannot already exist if specified by path and not
		 * appending to it unless user forces overwrite
		 */
		code = EEXIST;
		afs_com_err(pnp, code, "(use -force to overwrite)");
		goto cleanup;
	    }
	} else { /* file not found */
	    if (append) {
		code = ENOENT;
		afs_com_err(pnp, code, "(cannot append to non-existent file)");
		goto cleanup;
	    }
	}
	if (!append && !overWrite) { /* must create a new file in this case */
	    if ( BreakUpPath(fname, &dirName, &baseName) != 2 ) {
		code = EINVAL;
		afs_com_err(pnp, code, "(must provide full AFS path)");
		goto cleanup;
	    }

	    code = GetVenusFidByPath(dirName, cell, &dirvfp);
	    afscp_FreeFid(newvfp); /* release now-unneeded fid */
	    newvfp = NULL;
	    if (code != 0) {
		afs_com_err(pnp, code, "(is dir %s in AFS?)", dirName);
		goto cleanup;
	    }
	}
    }

    if ( (newvfp != NULL) && (newvfp->fid.Vnode & 1) ) {
	code = EISDIR;
	afs_com_err(pnp, code, "(%s is a directory, not a file)", fname);
	goto cleanup;
    }
    gettimeofday(&starttime, &Timezone);

    InStatus.UnixModeBits = 0644;
    InStatus.Mask = AFS_SETMODE + AFS_FSYNC;
    if (newvfp == NULL) {
	code = afscp_CreateFile(dirvfp, baseName, &InStatus, &newvfp);
	if (code != 0) {
	    afs_com_err(pnp, afscp_errno,
		        "(could not create file %s in directory %lu.%lu.%lu)",
		        baseName, afs_printable_uint32_lu(dirvfp->fid.Volume),
		        afs_printable_uint32_lu(dirvfp->fid.Vnode),
		        afs_printable_uint32_lu(dirvfp->fid.Unique));
	    goto cleanup;
	}
    }
    code = afscp_GetStatus(newvfp, &OutStatus);
    if (code != 0) {
	afs_inet_ntoa_r(newvfp->cell->fsservers[0]->addrs[0], ipv4_addr);
	afs_com_err(pnp, afscp_errno, "(failed to get status of file %s from"
		    "server %s, errno = %d)", fname, ipv4_addr, afscp_errno);
	goto cleanup;
    }

    if ( !append && !force &&
	 (OutStatus.Length != 0 || OutStatus.Length_hi !=0 ) ) {
	/*
	 * file exists, is of non-zero length, and we're not appending
	 * to it: user must force overwrite
	 * (covers fidwrite edge case)
	 */
	code = EEXIST;
	afs_com_err(pnp, code, "(use -force to overwrite)");
	goto cleanup;
    }

    if (append) {
	Pos = OutStatus.Length_hi;
	Pos = (Pos << 32) | OutStatus.Length;
    } else
	Pos = 0;
    previous = (struct wbuf *)&bufchain;
    if (md5sum)
	MD5_Init(&md5);

    /*
     * currently, these two while loops (1) read the whole source file in
     * before (2) writing any of it out, meaning that afsio can't deal with
     * files larger than the maximum amount of memory designated for
     * reading a file in (WRITEBUFLEN).
     * Consider going to a single loop, like in readFile(), though will
     * have implications on timing statistics (such as the "Startup to
     * find the file" time, below).
     */
    Len = 0;
    while (Len < WRITEBUFLEN) {
	tbuf = calloc(1, sizeof(struct wbuf));
	if (tbuf == NULL) {
	    if (!bufchain) {
		code = ENOMEM;
		afs_com_err(pnp, code, "(cannot allocate buffer)");
		goto cleanup;
	    }
	    break;
	}
	tbuf->buflen = BUFFLEN;
	if (synthesize) {
	    afs_int64 ll, l = tbuf->buflen;
	    if (l > synthlength)
		l = synthlength;
	    for (ll = 0; ll < l; ll += 4096) {
		sprintf(&tbuf->buf[ll], "Offset (0x%x, 0x%x)\n",
			(unsigned int)((offset + ll) >> 32),
			(unsigned int)((offset + ll) & 0xffffffff));
	    }
	    offset += l;
	    synthlength -= l;
	    tbuf->used = (afs_int32) l;
	} else
	    tbuf->used = read(0, &tbuf->buf, tbuf->buflen); /* from stdin */
	if (tbuf->used == 0) {
	    free(tbuf);
	    break;
	}
	if (md5sum)
	    MD5_Update(&md5, &tbuf->buf, tbuf->used);
	previous->next = tbuf;
	previous = tbuf;
	Len += tbuf->used;
    }
    gettimeofday(&opentime, &Timezone);
    if (verbose)
	fprintf(stderr, "Startup to find the file took %.3f sec.\n",
		time_elapsed(&starttime, &opentime));
    bytes = Len;
    while (!code && bytes) {
	Len = bytes;
	length = Len;
	if (Len) {
	    for (tbuf = bufchain; tbuf; tbuf = tbuf->next) {
		if (tbuf->used == 0)
		    break;
		byteswritten = afscp_PWrite(newvfp, tbuf->buf,
					    tbuf->used, Pos + xfered);
		if (byteswritten != tbuf->used) {
	            fprintf(stderr,"Only %d instead of %" AFS_INT64_FMT " bytes transferred by rx_Write()\n", byteswritten, length);
	            fprintf(stderr, "At %" AFS_UINT64_FMT " bytes from the end\n", length);
		    code = -4;
		    break;
		}
		xfered += tbuf->used;
		if (verbose)
		    printDatarate();
		length -= tbuf->used;
	    }
	}
	Pos += Len;
	bytes = 0;
	if (!code) {
	    for (tbuf = bufchain; tbuf; tbuf = tbuf->next) {
		tbuf->offset = 0;
		if (synthesize) {
		    afs_int64 ll, l = tbuf->buflen;
		    if (l > synthlength)
			l = synthlength;
		    for (ll = 0; ll < l; ll += 4096) {
			sprintf(&tbuf->buf[ll], "Offset (0x%x, 0x%x)\n",
				(unsigned int)((offset + ll) >> 32),
				(unsigned int)((offset + ll) & 0xffffffff));
		    }
		    offset += l;
		    synthlength -= l;
		    tbuf->used = (afs_int32) l;
		} else
		    tbuf->used = read(0, &tbuf->buf, tbuf->buflen); /* from stdin */
		if (!tbuf->used)
		    break;
		if (md5sum)
		    MD5_Update(&md5, &tbuf->buf, tbuf->used);
		Len += tbuf->used;
		bytes += tbuf->used;
	    }
	}
    }

    gettimeofday(&writetime, &Timezone);
    if (code) {
	afs_com_err(pnp, code, "(%s failed with code %d)", as->name,
		    code);
    } else if (verbose) {
	summarizeDatarate(&writetime, "write");
    }
    while (bufchain) {
	tbuf = bufchain;
	bufchain = tbuf->next;
	free(tbuf);
    }

    if (md5sum)
	summarizeMD5(fname);

cleanup:
    free(baseName);
    free(dirName);
    afscp_FreeFid(newvfp);
    afscp_FreeFid(dirvfp);
    return code;
} /* writeFile */

static int
removeFile(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 worstcode = 0;
    struct cmd_item *ti;

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear) {
	afscp_Insecure();
    }

    if (realm != NULL) {
	afscp_SetDefaultRealm(realm);
    }

    if (cell != NULL) {
	afscp_SetDefaultCell(cell);
    }

    for (ti = as->parms[0].items; ti != NULL; ti = ti->next) { /* -file */
	char *dirname, *basename;
	struct afscp_venusfid *parentfid = NULL;
	afs_int32 code = 0;

	parentfid = NULL;
	dirname = NULL;
	basename = NULL;

	fname = ti->data;
	code = GetParentFid(fname, &parentfid, &basename, &dirname);
	if (code != 0) {
	    afs_com_err(pnp, code,
			"(could not resolve parent fid: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	code = afscp_RemoveFile(parentfid, basename);
	if (code != 0) {
	    afs_com_err(pnp, afscp_errno,
			"(could not remove file: %s)", fname);
	    worstcode = afscp_errno;
	    goto cleanup;
	}

 cleanup:
	free(dirname);
	free(basename);
	afscp_FreeFid(parentfid);
    }
    return worstcode;
} /* removeFile */

static int
listAcl(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 worstcode = 0;
    struct cmd_item *ti;

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear) {
	afscp_Insecure();
    }

    if (realm != NULL) {
	afscp_SetDefaultRealm(realm);
    }

    if (cell != NULL) {
	afscp_SetDefaultCell(cell);
    }

    for (ti = as->parms[0].items; ti != NULL; ti = ti->next) { /* -dir, -fid */
	struct afscp_venusfid *avfp;
	struct aclu_Acl *parsed;
	struct aclu_AclEntry *te;
	struct aclu_rightsbuf buf;
	struct AFSOpaque acl;
	afs_int32 code;

	avfp = NULL;
	parsed = NULL;
	code = 0;
	memset(&acl, 0, sizeof(acl));

	fname = ti->data;
	if (useFid) {
	    code = GetVenusFidByFid(fname, cell, 0, &avfp);
	} else {
	    code = GetVenusFidByPath(fname, cell, &avfp);
	}
	if (code != 0) {
	    afs_com_err(pnp, code, "(directory not found: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	if ((avfp->fid.Vnode & 1) == 0) {
	    code = ENOENT;
	    afs_com_err(pnp, code, "(%s is a file, not a directory)", fname);
	    worstcode = code;
	    goto cleanup;
	}
	code = afscp_FetchACL(avfp, &acl);
	if (code != 0) {
	    afs_com_err(pnp, afscp_errno, "(failed to get ACL for %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	code = aclu_ParseAcl(acl.AFSOpaque_val, &parsed);
	if (code != 0) {
	    afs_com_err(pnp, code, "(failed to parse ACL string for %s)",
			fname);
	    worstcode = code;
	    goto cleanup;
	}
	if (parsed->dfs) {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(DCE/DFS is not supported by afsio for %s)",
			fname);
	    worstcode = code;
	    goto cleanup;
	}
	printf("Access list for %s is\n", fname);
	if (parsed->nplus > 0) {
	    printf("Normal rights:\n");
	    for (te = parsed->pluslist; te != NULL; te = te->next) {
		printf("  %s %s\n", te->name,
		       aclu_StringifyRights(te->rights, &buf));
	    }
	}
	if (parsed->nminus > 0) {
	    printf("Negative rights:\n");
	    for (te = parsed->minuslist; te != NULL; te = te->next) {
		printf("  %s %s\n", te->name,
		       aclu_StringifyRights(te->rights, &buf));
	    }
	}

 cleanup:
	aclu_FreeAcl(&parsed);
	xdr_free((xdrproc_t) xdr_AFSOpaque, &acl);
	afscp_FreeFid(avfp);
	if (ti->next != NULL) {
	    printf("\n");
	}
    }

    return worstcode;
} /* listAcl */

static int
setAcl(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 worstcode = 0;
    struct cmd_item *ti;

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear) {
	afscp_Insecure();
    }

    if (realm != NULL) {
	afscp_SetDefaultRealm(realm);
    }

    if (cell != NULL) {
	afscp_SetDefaultCell(cell);
    }

    for (ti = as->parms[0].items; ti != NULL; ti = ti->next) { /* -dir, -fid */
	char *result;
	struct AFSOpaque acl, storeacl;
	struct afscp_venusfid *avfp;
	struct aclu_Acl *parsed;
	struct aclu_aclbuf buf;
	int fatal;
	afs_int32 code;

	avfp = NULL;
	parsed = NULL;
	result = NULL;
	fatal = 0;
	code = 0;
	memset(&acl, 0, sizeof(acl));
	memset(&buf, 0, sizeof(buf));
	memset(&storeacl, 0, sizeof(storeacl));

	fname = ti->data;
	if (useFid) {
	    code = GetVenusFidByFid(fname, cell, 0, &avfp);
	} else {
	    code = GetVenusFidByPath(fname, cell, &avfp);
	}
	if (code != 0) {
	    afs_com_err(pnp, code, "(directory not found: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	if ((avfp->fid.Vnode & 1) == 0) {
	    code = ENOENT;
	    afs_com_err(pnp, code, "(%s is a file, not a directory)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	code = afscp_FetchACL(avfp, &acl);
	if (code != 0) {
	    afs_com_err(pnp, afscp_errno, "(failed to get ACL for %s)", fname);
	    worstcode = afscp_errno;
	    goto cleanup;
	}

	if (as->parms[2].items) { /* -clearacl */
	    code = aclu_ParseEmptyAcl(acl.AFSOpaque_val, &parsed);
	} else {
	    code = aclu_ParseAcl(acl.AFSOpaque_val, &parsed);
	}
	if (code != 0) {
	    afs_com_err(pnp, code, "(failed to parse/create ACL string for %s)",
			fname);
	    worstcode = code;
	    goto cleanup;
	}
	if (parsed->dfs) {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(DCE/DFS is not supported by afsio for %s)",
			fname);
	    worstcode = code;
	    goto cleanup;
	}
	CleanAcl(parsed, avfp->cell->name);

	code = UpdateAclEntries(as->parms[1].items, /* -acl */
				as->parms[3].items != NULL, /* -negative*/
				parsed);
	if (code != 0) {
	    worstcode = code;
	    fatal = 1;
	    goto cleanup;
	}

	result = aclu_AclToNetstring(parsed, &buf);
	if (result == NULL) {
	    afs_com_err(pnp, code, "(Failed to serialize ACL for %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	storeacl.AFSOpaque_val = buf.sbuf;
	storeacl.AFSOpaque_len = strlen(buf.sbuf) + 1;
	code = afscp_StoreACL(avfp, &storeacl);

	if (code != 0) {
	    afs_com_err(pnp, afscp_errno, "(failed to set ACL for %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

 cleanup:
	aclu_FreeAcl(&parsed);
	xdr_free((xdrproc_t) xdr_AFSOpaque, &acl);
	afscp_FreeFid(avfp);
	if (fatal) {
	    return worstcode;
	}
    }

    return worstcode;
} /* setAcl */

static int
listMount(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    afs_int32 worstcode = 0;
    struct cmd_item *ti;

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear) {
	afscp_Insecure();
    }

    if (realm != NULL) {
	afscp_SetDefaultRealm(realm);
    }

    if (cell != NULL) {
	afscp_SetDefaultCell(cell);
    }

    for (ti = as->parms[0].items; ti != NULL; ti = ti->next) { /* -dir, -fid */
	char *dirname, *basename;
	char buf[MOUNTSTR_MAX + 1];
	ssize_t bytes;
	struct afscp_venusfid *avfp, *parentfid;
	struct afscp_dirstream *parentdir;
	struct AFSFetchStatus status;
	afs_int32 code;

	avfp = NULL;
	parentfid = NULL;
	dirname = NULL;
	basename = NULL;
	parentdir = NULL;
	code = 0;
	memset(&status, 0, sizeof(status));
	memset(&buf, 0, sizeof(buf));

	fname = ti->data;
	if (useFid) {
	    code = GetVenusFidByFid(fname, cell, 0, &avfp);
	    if (code != 0) {
		afs_com_err(pnp, code, "(file not found: %s)", fname);
		worstcode = code;
		goto cleanup;
	    }
	} else {
	    code = GetParentFid(fname, &parentfid, &basename, &dirname);
	    if (code != 0) {
		afs_com_err(pnp, code,
			    "(could not resolve parent fid: %s)", fname);
		worstcode = code;
		goto cleanup;
	    }

	    parentdir = afscp_OpenDir(parentfid);
	    if (parentdir == NULL) {
		afs_com_err(pnp, afscp_errno,
			    "(could not open parent directory: %s)", dirname);
		worstcode = afscp_errno;
		goto cleanup;
	    }

	    avfp = afscp_DirLookup(parentdir, basename);
	    if (avfp == NULL) {
		afs_com_err(pnp, afscp_errno, "(could not look up mount of name"
			    " %s from parent directory %s)", basename, dirname);
		worstcode = afscp_errno;
		goto cleanup;
	    }
	}

	code = afscp_GetStatus(avfp, &status);
	if (code != 0) {
	    afs_com_err(pnp, afscp_errno, "(could not get status: %s)", fname);
	    worstcode = afscp_errno;
	    goto cleanup;
	}
	if (status.FileType != SymbolicLink ||
	    (status.UnixModeBits & 0111) != 0) {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(is not a valid mount point: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}
	if (status.Length_hi != 0 || status.Length > 1024) {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(mount point too large: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}

	bytes = afscp_PRead(avfp, buf, status.Length, 0);
	if (bytes < 0) {
	    afs_com_err(pnp, afscp_errno, "(failed to read mount point: %s)",
			fname);
	    worstcode = afscp_errno;
	    goto cleanup;
	}
	if (bytes != status.Length) {
	    code = EIO;
	    afs_com_err(pnp, code, "(short read on mount point: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}
	if (buf[0] != '#' && buf[0] != '%') {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(is not a valid mount point: %s)", fname);
	    worstcode = code;
	    goto cleanup;
	}
	buf[status.Length] = '\0';

	if (status.Length > 0 && buf[status.Length - 1] == '.') {
	    buf[status.Length - 1] = '\0';
	}
	printf("'%s' is a mount point for volume '%s'\n", fname, buf);

 cleanup:
	afscp_CloseDir(parentdir);
	free(dirname);
	free(basename);
	afscp_FreeFid(avfp);
	afscp_FreeFid(parentfid);
    }

    return worstcode;
} /* listMount */

static int
makeMount(struct cmd_syndesc *as, void *unused)
{
    char *fname = NULL;
    char *cell = NULL;
    char *realm = NULL;
    char *dirname = NULL, *basename = NULL;
    char *cellname = NULL, *volname = NULL;
    char *tmpname;
    char buf[MOUNTSTR_MAX + 1];
    afs_int32 code = 0, rwflag;
    struct afscp_venusfid *parentfid = NULL;
    struct AFSStoreStatus status;

    if (CmdProlog(as, &cell, &realm, &fname, NULL) != 0) {
	return -1;
    }

    afscp_AnonymousAuth(1);
    if (clear) {
	afscp_Insecure();
    }

    if (realm != NULL) {
	afscp_SetDefaultRealm(realm);
    }

    if (cell != NULL) {
	afscp_SetDefaultCell(cell);
    }

    volname = as->parms[1].items->data; /* -vol */
    if (strlen(volname) >= 64) {
	code = EINVAL;
	afs_com_err(pnp, code,
		    "(volume name too long, must be less than 64 chars: %s)",
		    volname);
	goto cleanup;
    }

    if (as->parms[2].items != NULL) { /* -mountcell */
	cellname = as->parms[2].items->data;
    }
    rwflag = (as->parms[3].items != NULL); /* -rw */

    code = GetParentFid(fname, &parentfid, &basename, &dirname);
    if (code != 0) {
	afs_com_err(pnp, code,
		    "(could not resolve parent fid: %s)", fname);
	goto cleanup;
    }

    tmpname = strchr(volname, ':');
    if (tmpname != NULL && cellname != NULL) {
	size_t cellsize;

	cellsize = tmpname - volname;
	if (strlen(cellname) != cellsize ||
	    strncmp(volname, cellname, cellsize) != 0) {
	    code = EINVAL;
	    afs_com_err(pnp, code, "(inconsistent cellnames given)");
	    goto cleanup;
	} else {
	    volname = tmpname + 1;
	}
    }

    if (as->parms[4].items == NULL) { /* -fast not provided */
	struct afscp_cell *tcell;
	struct afscp_volume *tvol;

	if (cellname == NULL) {
	    tcell = afscp_DefaultCell();
	} else {
	    tcell = afscp_CellByName(cellname, NULL);
	}

	/*
	 * Mirroring fs, only complain when we confirm the volume does not
	 * exist, i.e. we successfully obtained the cell and queried for the
	 * volume and we saw it did not exist
	 */
	if (tcell != NULL) {
	    tvol = afscp_VolumeByName(tcell, volname, rwflag ? RWVOL : ROVOL);
	    if (tvol == NULL) {
		code = EINVAL;
		afs_com_err(pnp, code,
			    "(warning, volume %s does not exist in cell %s)",
			    volname, tcell->name);
	    }
	}
    }

    if (cellname == NULL) {
	code = snprintf(buf, sizeof(buf), "%s%s.", rwflag ? "%" : "#", volname);
    } else {
	code = snprintf(buf, sizeof(buf), "%s%s:%s.", rwflag ? "%" : "#",
			cellname, volname);
    }

    if (code < 0 || (size_t)code >= sizeof(buf)) {
	code = EINVAL;
	afs_com_err(pnp, code, "(could not assemble mount point string: %s)",
		    fname);
	goto cleanup;
    }

    memset(&status, 0, sizeof(status));
    status.UnixModeBits = 0644;
    status.ClientModTime = time(NULL);
    status.Mask = AFS_SETMODE | AFS_SETMODTIME;

    code = afscp_Symlink(parentfid, basename, buf, &status);
    if (code != 0) {
	code = afscp_errno;
	afs_com_err(pnp, afscp_errno,
		    "(could not create mount point %s in directory %lu.%lu.%lu)",
		    basename,
		    afs_printable_uint32_lu(parentfid->fid.Volume),
		    afs_printable_uint32_lu(parentfid->fid.Vnode),
		    afs_printable_uint32_lu(parentfid->fid.Unique));
	goto cleanup;
    }

 cleanup:
    free(dirname);
    free(basename);
    afscp_FreeFid(parentfid);

    return code;
} /* makeMount */