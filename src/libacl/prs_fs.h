/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
	Information Technology Center
	Carnegie-Mellon University
*/


#ifndef _PRSFS_
#define _PRSFS_

/*
An access list is associated with each directory.  Possession of each of the following rights allows
the possessor the corresponding privileges on ALL files in that directory
*/
#define PRSFS_READ            1	/*Read files */
#define PRSFS_WRITE           2	/*Write and write-lock existing files */
#define PRSFS_INSERT          4	/*Insert and write-lock new files */
#define PRSFS_LOOKUP          8	/*Enumerate files and examine access list */
#define PRSFS_DELETE          16	/*Remove files */
#define PRSFS_LOCK            32	/*Read-lock files */
#define PRSFS_ADMINISTER      64	/*Set access list of directory */

/* user space rights */
#define PRSFS_USR0	      0x01000000
#define PRSFS_USR1	      0x02000000
#define PRSFS_USR2	      0x04000000
#define PRSFS_USR3	      0x08000000
#define PRSFS_USR4	      0x10000000
#define PRSFS_USR5	      0x20000000
#define PRSFS_USR6	      0x40000000
#define PRSFS_USR7	      0x80000000

/*
 * Mods for the AFS/DFS protocol translator.
 *
 * DFS rights. It's ugly to put these definitions here, but they
 * *cannot* change, because they're part of the wire protocol.
 * In any event, the protocol translator will guarantee these
 * assignments for AFS cache managers.
 */
# define DFS_READ          0x01
# define DFS_WRITE         0x02
# define DFS_EXECUTE       0x04
# define DFS_CONTROL       0x08
# define DFS_INSERT        0x10
# define DFS_DELETE        0x20

/* the application definable ones (backwards from AFS) */
# define DFS_USR0 0x80000000	/* "A" bit */
# define DFS_USR1 0x40000000	/* "B" bit */
# define DFS_USR2 0x20000000	/* "C" bit */
# define DFS_USR3 0x10000000	/* "D" bit */
# define DFS_USR4 0x08000000	/* "E" bit */
# define DFS_USR5 0x04000000	/* "F" bit */
# define DFS_USR6 0x02000000	/* "G" bit */
# define DFS_USR7 0x01000000	/* "H" bit */
# define DFS_USRALL	(DFS_USR0 | DFS_USR1 | DFS_USR2 | DFS_USR3 |\
			 DFS_USR4 | DFS_USR5 | DFS_USR6 | DFS_USR7)
#endif
