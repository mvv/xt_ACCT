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

#ifndef XT_ACCT_H
#define XT_ACCT_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifdef __KERNEL__
# include <linux/in.h>
# include <linux/in6.h>
#else
# include <netinet/in.h>
#endif

#define IPT_ACCT_NAME  "ipt_ACCT"
#define IP6T_ACCT_NAME "ip6t_ACCT"

#define XT_ACCT_DEFAULT_SIZE     4096
#define XT_ACCT_DEFAULT_INTERVAL 5

#define XT_ACCT_IOCTL_SETUP _IO  ('C', 0)

struct xt_acct_stat {
	u_int64_t enabled_ts;
	u_int64_t pkts_acct;
	u_int64_t bytes_acct;
	u_int64_t pkts_not_acct;
	u_int64_t bytes_not_acct;
};

struct ipt_acct_record {
	struct in_addr src;
	struct in_addr dst;
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t npkts;
	u_int64_t nbytes;
	u_int64_t first_ts;
	u_int64_t last_ts;
	u_int32_t tag;
	u_int32_t conn_mark;
	u_int8_t proto;
};

struct ip6t_acct_record {
	struct in6_addr src;
	struct in6_addr dst;
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t npkts;
	u_int64_t nbytes;
	u_int64_t first_ts;
	u_int64_t last_ts;
	u_int32_t tag;
	u_int32_t conn_mark;
	u_int8_t proto;
};

#endif /* XT_ACCT_H */

