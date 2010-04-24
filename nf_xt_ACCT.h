/*
 * Copyright (C) 2010 Mikhail Vorozhtsov
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef NF_XT_ACCT_H
#define NF_XT_ACCT_H

#ifdef __KERNEL__
# include <linux/list.h>
struct xt_acct_pool_ref;
#endif

#define XT_ACCT_AGGR_SRC   1
#define XT_ACCT_AGGR_DST   2
#define XT_ACCT_AGGR_SPORT 4
#define XT_ACCT_AGGR_DPORT 8
#define XT_ACCT_AGGR_PROTO 16
#define XT_ACCT_AGGR_CONN  32
#define XT_ACCT_AGGR_ALL   63

struct xt_acct_target_info
{
	u_int32_t tag; 
	u_int8_t aggr_by;
	u_int8_t master_src : 1;
	u_int8_t add_llh_size : 1;
	u_int8_t smask;
	u_int8_t dmask;
	u_int16_t pool_id;
	unsigned int unavail_retcode;
	unsigned int unacct_retcode;
	unsigned int retcode;
	union {
#ifdef __KERNEL__
		struct {
			struct list_head list_node;
			struct xt_acct_pool_ref *pool_ref;
		};
#endif
		u_int64_t __words[3];
	} kernel_data;
};

#endif /* NF_XT_ACCT_H */

