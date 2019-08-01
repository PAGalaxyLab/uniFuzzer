/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2000-2005 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Lesser General Public License version 2.1 or later.
 */

#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <string.h>
#include <stdio.h>
#include <unistd.h>


static char *_dl_get_last_path_component(char *path);

static __always_inline char * _dl_get_last_path_component(char *path)
{
	register char *ptr = path-1;

	while (*++ptr)
		;/* empty */

	/* strip trailing slashes */
	while (ptr != path && *--ptr == '/') {
		*ptr = '\0';
	}

	/* find last component */
	while (ptr != path && *--ptr != '/')
		;/* empty */
	return ptr == path ? ptr : ptr+1;
}

#endif
