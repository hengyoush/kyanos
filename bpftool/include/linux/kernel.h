/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#ifndef __LINUX_KERNEL_H
#define __LINUX_KERNEL_H

#include <linux/build_bug.h>

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#ifndef max
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#endif

#ifndef roundup
#define roundup(x, y) (				\
{						\
	const typeof(y) __y = y;		\
	(((x) + (__y - 1)) / __y) * __y;	\
}						\
)
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#endif
