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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/rbtree.h>

#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/proc_fs.h>
#include <linux/configfs.h>

#define IPT_ACCT @IPT_ACCT@
#define IP6T_ACCT (!@IPT_ACCT@)

#if IPT_ACCT
# include <linux/netfilter_ipv4.h>
#else
# include <net/ipv6.h>
# include <linux/netfilter_ipv6.h>
#endif

#include <linux/netfilter/x_tables.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <net/sctp/sctp.h>
#include <linux/dccp.h>

#if IPT_ACCT
# if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#   if defined(CONFIG_IP_NF_CONNTRACK) \
       || defined(CONFIG_IP_NF_CONNTRACK_MODULE)
#     include <net/netfilter/nf_conntrack_compat.h>
#     define XT_ACCT_CT_IPV4
#     define XT_ACCT_CT
#     ifdef CONFIG_IP_NF_CONNTRACK_MARK
#       define XT_ACCT_CT_MARK
#     endif
#   endif
# endif
#endif /* IPT_ACCT */
#ifndef XT_ACCT_CT_IPV4
# if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#   include <net/netfilter/nf_conntrack.h>
#   define XT_ACCT_CT_GENERIC
#   define XT_ACCT_CT
#   ifdef CONFIG_NF_CONNTRACK_MARK
#     define XT_ACCT_CT_MARK
#   endif
# endif
#endif /* !XT_ACCT_CT_IPV4 */

#include "nf_xt_ACCT.h"
#include "xt_ACCT.h"

#if IPT_ACCT
# define XT_ACCT_NAME IPT_ACCT_NAME
# define xt_acct_record ipt_acct_record
#else
# define XT_ACCT_NAME IP6T_ACCT_NAME
# define xt_acct_record ip6t_acct_record
#endif

#if IPT_ACCT
# define IP_MASK_MAX 32
#else
# define IP_MASK_MAX 128
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikhail Vorozhtsov <mikhail.vorozhtsov@gmail.com>");
#if IPT_ACCT
MODULE_DESCRIPTION("iptables accounting module");
#else
MODULE_DESCRIPTION("ip6tables accounting module");
#endif

static const unsigned int primes[] =
{
	13, 19, 29, 41, 59, 79, 107, 149, 197, 263, 347, 457, 599, 787, 1031,
	1361, 1777, 2333, 3037, 3967, 5167, 6719, 8737, 11369, 14783,
	19219, 24989, 32491, 42257, 54941, 71429, 92861, 120721, 156941,
	204047, 265271, 344857, 448321
};

struct xt_acct_records_list {
	struct xt_acct_records_list *next;
	struct xt_acct_record *record;
};

struct xt_acct_hash_bucket {
	struct xt_acct_records_list *list;
	unsigned long ts;
};

struct xt_acct_pool_ref;

struct xt_acct_target_kdata {
	struct list_head list_node;
	struct xt_acct_pool_ref *pool_ref;
	u32 smask;
	u32 dmask;
};

struct xt_acct_pool {
	u16 id;
	struct xt_acct_pool_ref *ref;
	int state;
	bool disabling_pending;
	spinlock_t state_lock;

#define STATE_ENABLED    1
#define STATE_DISABLED   0
#define STATE_ENABLING   (-1)
#define STATE_DISABLING  (-2)
#define STATE_DEAD       (-3)

	struct {
		/* Pool size in records. */
		unsigned int size;
		/* Aggregation interval. */
		unsigned int interval;
		/* Whether to disallow accounting more packets. */
		atomic_t ro_mode;
	} cfg;

	struct xt_acct_stat stat;
	spinlock_t stat_lock;

	struct xt_acct_records_list *lists;
	struct xt_acct_record *records;
	struct xt_acct_record *records_end;
	struct xt_acct_record *ready_record;
	unsigned int ready_cnt;
	spinlock_t ready_ptr_lock;
	spinlock_t read_lock;
	struct xt_acct_record *used_record;
	unsigned int used_cnt;
	struct xt_acct_record *free_record;
	unsigned int free_cnt;
	unsigned long last_ts;
	spinlock_t acct_lock;

	struct xt_acct_hash_bucket *hashtab;
	unsigned int hashtab_size;

	struct kref refs_cnt;
	struct timer_list timer;
	atomic_t timer_flag;
	unsigned long timer_jiffies;
	struct config_item cfg_item;
};

#define XT_ACCT_POOL(item) \
	container_of((item), struct xt_acct_pool, cfg_item)

static void xt_acct_pool_release(struct kref *kref)
{
	struct xt_acct_pool *pool = container_of(kref, struct xt_acct_pool,
				                 refs_cnt);
	kfree(pool);
}

static bool xt_acct_pool_data_get(struct xt_acct_pool *pool)
{
	bool ret;

	spin_lock_bh(&pool->state_lock);
	ret = (pool->state >= STATE_ENABLED) && !pool->disabling_pending;
	if (ret)
		pool->state += 1;
	spin_unlock_bh(&pool->state_lock);

	return ret;
}

static void xt_acct_pool_data_put(struct xt_acct_pool *pool)
{
	spin_lock_bh(&pool->state_lock);
	pool->state -= 1;
	spin_unlock_bh(&pool->state_lock);
}

static inline void xt_acct_pool_get(struct xt_acct_pool *pool)
{
	if (pool)
		kref_get(&pool->refs_cnt);
}

static inline void xt_acct_pool_put(struct xt_acct_pool *pool)
{
	kref_put(&pool->refs_cnt, xt_acct_pool_release);
}

struct xt_acct_pool_ref {
	struct rb_node rb_node;

	/*
	 * References (from targets, file descriptors, and the pool) counter.
	 * Guarded by pool_refs_lock.
	 */
	unsigned int refs_cnt;

	/* Waked up whenever the pool has new records ready for reading. */
	wait_queue_head_t wq;

	u16 pool_id;
	struct xt_acct_pool *pool;
	spinlock_t pool_lock;

	/* List of xtables targets. */
	struct list_head targets;
	spinlock_t targets_lock;

	/* List of opened file descriptors. */
	struct list_head files;
	spinlock_t files_lock;
};

static struct rb_root pool_refs = RB_ROOT;
static DEFINE_SPINLOCK(pool_refs_lock);

struct xt_acct_proc_pdata {
	struct xt_acct_pool_ref *pool_ref;
	rwlock_t setup_lock;
	struct list_head list_node;
};

static inline struct xt_acct_pool *
xt_acct_pool_ref_deref(struct xt_acct_pool_ref *ref)
{
	struct xt_acct_pool *pool;

	spin_lock_bh(&ref->pool_lock);
	pool = ref->pool;
	xt_acct_pool_get(pool);
	spin_unlock_bh(&ref->pool_lock);

	return pool;
}

static void xt_acct_pool_ref_put(struct xt_acct_pool_ref *ref) {
	bool free;

	spin_lock_bh(&pool_refs_lock);
	ref->refs_cnt -= 1;
	free = ref->refs_cnt == 0;
	if (free)
		rb_erase(&ref->rb_node, &pool_refs);
	spin_unlock_bh(&pool_refs_lock);

	if (free)
		kfree(ref);
}

static struct xt_acct_pool_ref *xt_acct_pool_ref_lookup(u16 pool_id)
{
	struct rb_node *n = pool_refs.rb_node;
	struct xt_acct_pool_ref *r;

	while (n) {
		r = rb_entry(n, struct xt_acct_pool_ref, rb_node);

		if (pool_id < r->pool_id)
			n = n->rb_left;
		else if (pool_id > r->pool_id)
			n = n->rb_right;
		else
			return r;
	}

	return NULL;
}

static void xt_acct_pool_ref_insert(struct xt_acct_pool_ref *ref)
{
	struct rb_node **p = &pool_refs.rb_node;
	struct rb_node *parent = NULL;
	struct xt_acct_pool_ref *r = NULL;

	while (*p) {
		parent = *p;
		r = rb_entry(parent, struct xt_acct_pool_ref, rb_node);

		if (ref->pool_id < r->pool_id)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&ref->rb_node, parent, p);
        rb_insert_color(&ref->rb_node, &pool_refs);
}

static struct xt_acct_pool_ref *
xt_acct_pool_ref_create(u16 pool_id, struct xt_acct_pool *pool,
                        struct xt_acct_target_kdata *kdata,
                        struct xt_acct_proc_pdata *pdata)
{
	struct xt_acct_pool_ref *ref;

	spin_lock_bh(&pool_refs_lock);

	ref = xt_acct_pool_ref_lookup(pool_id);

	if (!ref) {
		ref = kzalloc(sizeof(struct xt_acct_pool_ref), GFP_ATOMIC);

		if (!ref) {
			spin_unlock_bh(&pool_refs_lock);
			if (kdata)
				printk(KERN_ERR KBUILD_MODNAME
			          ": cannot allocate a pool reference\n");
			return ERR_PTR(-ENOMEM);
		}

		ref->pool_id = pool_id;
		ref->pool = pool;
		spin_lock_init(&ref->pool_lock);
		INIT_LIST_HEAD(&ref->targets);
		spin_lock_init(&ref->targets_lock);
		INIT_LIST_HEAD(&ref->files);
		spin_lock_init(&ref->files_lock);

		init_waitqueue_head(&ref->wq);
		ref->refs_cnt = 1;

		if (pool)
			pool->ref = ref;
		else if (kdata) {
			list_add(&kdata->list_node, &ref->targets);
			kdata->pool_ref = ref;
		} else if (pdata) {
			list_add(&pdata->list_node, &ref->files);
			pdata->pool_ref = ref;
		}

		xt_acct_pool_ref_insert(ref);
	} else {
		ref->refs_cnt += 1;

		if (pool) {
			spin_lock_bh(&ref->pool_lock);
			ref->pool = pool;
			pool->ref = ref;
			spin_unlock_bh(&ref->pool_lock);
		} else if (kdata) {
			spin_lock_bh(&ref->targets_lock);
			list_add(&kdata->list_node, &ref->targets);
			spin_unlock_bh(&ref->targets_lock);
			kdata->pool_ref = ref;
		} else if (pdata) {
			spin_lock_bh(&ref->files_lock);
			list_add(&pdata->list_node, &ref->files);
			spin_unlock_bh(&ref->files_lock);
			pdata->pool_ref = ref;
		}
	}

	spin_unlock_bh(&pool_refs_lock);

	return ref;
}

#if IPT_ACCT
static inline int ipv4_proto(struct sk_buff *skb,
                             struct iphdr *iph, u8 *proto)
{
	*proto = iph->protocol;
	return ip_hdrlen(skb);
}

static inline unsigned int ipv4_hash(struct in_addr *src, struct in_addr *dst,
                                     u16 sport, u16 dport, u8 proto,
				     u32 conn_mark)
{
	u32 words[] = {
		src->s_addr,
		dst->s_addr,
		((u32) sport << 16) | (u32) dport,
		conn_mark
	};
	return jhash2(words, ARRAY_SIZE(words), proto);
}
#else
static inline int ipv6_proto(struct sk_buff *skb, struct ipv6hdr *iph,
                             u8 *proto)
{
	u8 nexthdr = iph->nexthdr;
	int result = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr);

	if (result > 0)
		*proto = nexthdr;

	return result;
}

static inline unsigned int ipv6_hash(struct in6_addr *src,
                                     struct in6_addr *dst,
                                     u16 sport, u16 dport, u8 proto,
                                     u32 conn_mark)
{
	u32 words[] = {
		src->s6_addr32[0],
		src->s6_addr32[1],
		src->s6_addr32[2],
		src->s6_addr32[3],
		dst->s6_addr32[0],
		dst->s6_addr32[1],
		dst->s6_addr32[2],
		dst->s6_addr32[3],
		((u32) sport << 16) | (u32) dport,
		conn_mark
	};
	return jhash2(words, ARRAY_SIZE(words), proto);
}

static inline void ipv6_mask(struct in6_addr *addr, u8 bits, u32 mask)
{
	if (bits == 128)
		;
	else if (bits >= 96)
		addr->s6_addr32[3] &= mask;
	else if (bits >= 64) {
		addr->s6_addr32[2] &= mask;
		addr->s6_addr32[3] = 0;
	} else if (bits >= 32) {
		addr->s6_addr32[1] &= mask;
		addr->s6_addr32[2] = 0;
		addr->s6_addr32[3] = 0;
	} else {
		addr->s6_addr32[0] &= mask;
		addr->s6_addr32[1] = 0;
		addr->s6_addr32[2] = 0;
		addr->s6_addr32[3] = 0;
	}
}
#endif

static unsigned int xt_acct_pool_ready_used(struct xt_acct_pool *pool,
                                            unsigned long aligned_ts)
{
	bool aligned_ts_provided = aligned_ts != 0;
	unsigned long ts;
	unsigned int ready_cnt = 0;

	if (!aligned_ts_provided) {
		ts = get_seconds();
		aligned_ts = ts - (ts % pool->cfg.interval);
	}

	if (pool->last_ts != aligned_ts) {
		spin_lock_bh(&pool->ready_ptr_lock);
		if (pool->ready_cnt == 0)
			pool->ready_record = pool->used_record;
		pool->ready_cnt += pool->used_cnt;
		ready_cnt = pool->ready_cnt;
		spin_unlock_bh(&pool->ready_ptr_lock);

		pool->used_record = NULL;
		pool->used_cnt = 0;
			
		pool->last_ts = aligned_ts;
	} else if (!aligned_ts_provided) {
		spin_lock_bh(&pool->ready_ptr_lock);
		ready_cnt = pool->ready_cnt;
		spin_unlock_bh(&pool->ready_ptr_lock);
	}

	return ready_cnt;
}

static unsigned int xt_acct_target_handle(
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 24)
		struct sk_buff **pskb,
#else
		struct sk_buff *skb,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
		const struct net_device *in, const struct net_device *out,
		unsigned int hook_number, const struct xt_target *target,
		const void *target_info
# if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
		, void *user_info 
# endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 35)
		const struct xt_target_param *param
#else
		const struct xt_action_param *param
#endif
		)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 24)
	struct sk_buff *skb = *pskb;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) target_info;
#else
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) param->targinfo;
#endif
	struct xt_acct_target_kdata *kdata = info->kdata;
	bool accounted = true;
	unsigned int ret = info->retcode;

#if IPT_ACCT
# define IP_HDR ip_hdr
# define IP_PROTO ipv4_proto
# define IP_SIZE(iph) ntohs((iph)->tot_len)
# define IP_HASH ipv4_hash
# define IP_ADDR_EQ(a1,a2) ((a1).s_addr == (a2).s_addr)
# define IP_ADDR_COPY(a1,a2) \
	((a2).s_addr = ((struct in_addr *) &(a1))->s_addr)
# define IP_ADDR_MASK(addr,bits,mask) \
	((bits) == 32 ? (addr).s_addr : ((addr).s_addr &= (mask)))
	struct iphdr *iph;
	struct in_addr src = { .s_addr = 0 }, dst = { .s_addr = 0 };
#else
# define IP_HDR ipv6_hdr
# define IP_PROTO ipv6_proto
# define IP_SIZE(iph) \
	(sizeof(struct ipv6hdr) + ntohl((iph)->payload_len))
# define IP_HASH ipv6_hash
# define IP_ADDR_EQ(a1,a2)                              \
	((a1).s6_addr32[0] == (a2).s6_addr32[0]         \
	 && (a1).s6_addr32[1] == (a2).s6_addr32[1]      \
	 && (a1).s6_addr32[2] == (a2).s6_addr32[2]      \
	 && (a1).s6_addr32[3] == (a2).s6_addr32[3])
# define IP_ADDR_COPY(a1,a2)                            \
	do {                                            \
		(a2).s6_addr32[0] = (a1).s6_addr32[0];  \
		(a2).s6_addr32[1] = (a1).s6_addr32[1];  \
		(a2).s6_addr32[2] = (a1).s6_addr32[2];  \
		(a2).s6_addr32[3] = (a1).s6_addr32[3];  \
	} while(0);
# define IP_ADDR_MASK(addr,bits,mask) ipv6_mask(&(addr), (bits), (mask))
	struct ipv6hdr *iph;
	struct in6_addr src = IN6ADDR_ANY_INIT, dst = IN6ADDR_ANY_INIT;
#endif
	int thoff;
	union {
		struct {
			struct tcphdr _tcph;
			struct tcphdr *tcph;
		};
		struct {
			struct udphdr _udph;
			struct udphdr *udph;
		};
		struct {
			struct sctphdr _sctph;
			struct sctphdr *sctph;
		};
		struct {
			struct dccp_hdr _dccph;
			struct dccp_hdr *dccph;
		};
	} th;
	u16 sport = 0, dport = 0;
	u32 size;
	u8 proto = 0;
#ifdef XT_ACCT_CT_IPV4
	struct ip_conntrack *ct = NULL;
        u32 ctinfo;
	struct ip_conntrack_tuple *tuple;
#elif defined(XT_ACCT_CT_GENERIC)
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple *tuple;
#endif
	u32 conn_mark = 0;
	bool need_src_info;
	unsigned long ts, aligned_ts;

	struct xt_acct_pool_ref *ref;
	struct xt_acct_pool *pool;
	struct xt_acct_hash_bucket *bucket = NULL;
	struct xt_acct_records_list *node;
	struct xt_acct_record *record;
	unsigned int i;
	bool ready;

	iph = IP_HDR(skb);

	if (!(info->aggr_by & (XT_ACCT_AGGR_SPORT | XT_ACCT_AGGR_DPORT
			       | XT_ACCT_AGGR_PROTO)))
		goto no_th;

	thoff = IP_PROTO(skb, iph, &proto);

	if (thoff < 0)
		goto no_th;

	if (!(info->aggr_by
	      & (XT_ACCT_AGGR_SPORT | XT_ACCT_AGGR_DPORT)))
		goto no_th;

	switch (proto) {
	case IPPROTO_TCP:
		th.tcph = skb_header_pointer(
		            skb, thoff, sizeof(th._tcph), &th._tcph);

		if (!th.tcph)
			goto no_th;

		if (info->aggr_by & XT_ACCT_AGGR_SPORT)
			sport = ntohs(th.tcph->source);
		if (info->aggr_by & XT_ACCT_AGGR_DPORT)
			dport = ntohs(th.tcph->dest);
		break;
	case IPPROTO_UDP:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
	case IPPROTO_UDPLITE:
#endif
		th.udph = skb_header_pointer(
		            skb, thoff, sizeof(th._udph), &th._udph);

		if (!th.udph)
			goto no_th;

		if (info->aggr_by & XT_ACCT_AGGR_SPORT)
			sport = ntohs(th.udph->source);
		if (info->aggr_by & XT_ACCT_AGGR_DPORT)
			dport = ntohs(th.udph->dest);
		break;
	case IPPROTO_SCTP:
		th.sctph = skb_header_pointer(
		             skb, thoff, sizeof(th._sctph), &th._sctph);

		if (!th.sctph)
			goto no_th;

		if (info->aggr_by & XT_ACCT_AGGR_SPORT)
			sport = ntohs(th.sctph->source);
		if (info->aggr_by & XT_ACCT_AGGR_DPORT)
			dport = ntohs(th.sctph->dest);
		break;
	case IPPROTO_DCCP:
		th.dccph = skb_header_pointer(
		             skb, thoff, sizeof(th._dccph), &th._dccph);

		if (!th.dccph)
			goto no_th;

		if (info->aggr_by & XT_ACCT_AGGR_SPORT)
			sport = ntohs(th.dccph->dccph_sport);
		if (info->aggr_by & XT_ACCT_AGGR_DPORT)
			dport = ntohs(th.dccph->dccph_dport);
		break;
	}

no_th:
	if (info->aggr_by & XT_ACCT_AGGR_SRC)
		IP_ADDR_COPY(iph->saddr, src);
	if (info->aggr_by & XT_ACCT_AGGR_DST)
		IP_ADDR_COPY(iph->daddr, dst);

	need_src_info = info->aggr_by
	                & (XT_ACCT_AGGR_SRC | XT_ACCT_AGGR_SPORT);

#ifdef XT_ACCT_CT
	if (
# ifdef XT_ACCT_CT_MARK
            info->aggr_by & XT_ACCT_AGGR_CONN
# else
            0
# endif
	    || (need_src_info && info->master_src)) {
# ifdef XT_ACCT_CT_IPV4
		ct = ip_conntrack_get(skb, &ctinfo);
# else
		ct = nf_ct_get(skb, &ctinfo);
# endif
		
		if (!ct)
			goto no_more_ct;

# ifdef XT_ACCT_CT_MARK
		if (info->aggr_by & XT_ACCT_AGGR_CONN)
			conn_mark = ct->mark;
# endif

		if (!need_src_info || !ct->master)
			goto no_more_ct;

		tuple = &ct->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

# ifdef XT_ACCT_CT_IPV4
		if (!ip_ct_tuple_dst_equal(
# else
#   if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
		if (!nf_ct_tuple_dst_equal(
#   else
		if (!__nf_ct_tuple_dst_equal(
#   endif
# endif
		         &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple, tuple))
			goto no_more_ct;

		if (info->aggr_by & XT_ACCT_AGGR_SRC) {
# if IPT_ACCT
#   ifdef XT_ACCT_CT_IPV4
			src.s_addr = tuple->src.ip;
#   else
			src.s_addr = tuple->src.u3.ip;
#   endif
# else
			src.s6_addr32[0] = tuple->src.u3.ip6[0];
			src.s6_addr32[1] = tuple->src.u3.ip6[1];
			src.s6_addr32[2] = tuple->src.u3.ip6[2];
			src.s6_addr32[3] = tuple->src.u3.ip6[3];
# endif
		}

		if (info->aggr_by & XT_ACCT_AGGR_SPORT && sport != 0)
			sport = tuple->src.u.all;
	}

no_more_ct:
#endif /* XT_ACCT_CT */

	if (info->aggr_by & XT_ACCT_AGGR_SRC)
		IP_ADDR_MASK(src, info->smask, kdata->smask);
	if (info->aggr_by & XT_ACCT_AGGR_SRC)
		IP_ADDR_MASK(dst, info->dmask, kdata->dmask);

	size = IP_SIZE(iph);

	if (info->add_llh_size)
		size += skb->mac_len;

	i = IP_HASH(&src, &dst, sport, dport, proto, conn_mark);

	ref = kdata->pool_ref;
	pool = xt_acct_pool_ref_deref(ref);

	if (!pool)
		return info->unavail_retcode;

	if (!xt_acct_pool_data_get(pool)) {
		xt_acct_pool_put(pool);
		return info->unavail_retcode;
	}

	if (atomic_read(&pool->cfg.ro_mode)) {
		xt_acct_pool_put(pool);
		return info->unavail_retcode;
	}

	spin_lock_bh(&pool->acct_lock);

	ts = get_seconds();

	if (pool->cfg.interval == 0) {
		node = NULL;
		goto allocate_record;
	}

	aligned_ts = ts - (ts % pool->cfg.interval);
	xt_acct_pool_ready_used(pool, aligned_ts);

	i = i % pool->hashtab_size;
	bucket = &pool->hashtab[i];

	if (bucket->ts != aligned_ts) {
		bucket->list = NULL;
		bucket->ts = aligned_ts;
	}

	for (node = bucket->list; node; node = node->next) {
		record = node->record;

		if (record->tag == info->tag
		    && IP_ADDR_EQ(record->src, src)
		    && IP_ADDR_EQ(record->dst, dst)
		    && record->sport == sport
		    && record->dport == dport
		    && record->proto == proto
		    && record->conn_mark == conn_mark)
			break;
	}

allocate_record:
	if (!node) {
		if (pool->free_record) {
			node = pool->lists
			       + (pool->free_record - pool->records);
			record = pool->free_record;

			if (pool->cfg.interval > 0)
				node->record = pool->free_record;

			pool->free_cnt -= 1;

			if (pool->free_cnt == 0)
				pool->free_record = NULL;
			else if (pool->free_record + 1 == pool->records_end)
				pool->free_record = pool->records;
			else
				pool->free_record += 1;

			if (pool->cfg.interval > 0) {
				if (pool->used_record == NULL)
					pool->used_record = record;
				pool->used_cnt += 1;
			}
		} else
			record = NULL;

		if (!record) {
			accounted = false;
			ret = info->unacct_retcode;
			goto unlock_acct;
		}

		if (pool->cfg.interval > 0) {
			node->next = bucket->list;
			bucket->list = node;
		}

		IP_ADDR_COPY(src, record->src);
		IP_ADDR_COPY(dst, record->dst);
		record->sport = sport;
		record->dport = dport;
		record->proto = proto;
		record->conn_mark = conn_mark;
		record->npkts = 0;
		record->nbytes = 0;
		record->first_ts = ts;
		record->tag = info->tag;
	} else
		record = node->record;

	record->npkts += 1;
	record->nbytes += size;
	record->last_ts = ts;

	if (pool->cfg.interval == 0) {
		spin_lock_bh(&pool->ready_ptr_lock);
		if (pool->ready_cnt == 0)
			pool->ready_record = record;
		pool->ready_cnt += 1;
		spin_unlock_bh(&pool->ready_ptr_lock);
	}

unlock_acct:
	spin_unlock_bh(&pool->acct_lock);

	spin_lock_bh(&pool->stat_lock);

	if (accounted) {
		pool->stat.pkts_acct += 1;
		pool->stat.bytes_acct += size;
	} else {
		pool->stat.pkts_not_acct += 1;
		pool->stat.bytes_not_acct += size;
	}

	spin_unlock_bh(&pool->stat_lock);

	spin_lock_bh(&pool->ready_ptr_lock);
	ready = pool->ready_cnt > 0;
	spin_unlock_bh(&pool->ready_ptr_lock);

	xt_acct_pool_data_put(pool);
	xt_acct_pool_put(pool);

	if (ready)
		wake_up(&ref->wq);

	return ret;
}

static
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 23) \
    || LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 35)
int
#else
bool
#endif
xt_acct_target_check(
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
		const char *table_name, const void *entry,
		const struct xt_target *target,
		void *target_info,
# if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
		unsigned int target_info_size,
# endif
		unsigned int hook_mask
#else
		const struct xt_tgchk_param *param
#endif
		)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) target_info;
#else
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) param->targinfo;
#endif
	struct xt_acct_target_kdata *kdata;
	struct xt_acct_pool_ref *ref;
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 35)
# define SUCCESS_RET 1
# define INVAL_RET 0
# define NOMEM_RET 0
#else
# define SUCCESS_RET 0
# define INVAL_RET -EINVAL
# define NOMEM_RET -ENOMEM
#endif

	if (info->aggr_by & XT_ACCT_AGGR_SRC && info->smask > IP_MASK_MAX) {
		printk(KERN_ERR KBUILD_MODNAME ": invalid source mask %u\n",
		       info->smask);
		return INVAL_RET;
	}

	if (info->aggr_by & XT_ACCT_AGGR_DST && info->dmask > IP_MASK_MAX) {
		printk(KERN_ERR KBUILD_MODNAME
		       ": invalid destination mask %u\n", info->dmask);
		return INVAL_RET;
	}

	switch (info->unavail_retcode) {
	case XT_CONTINUE:
	case NF_ACCEPT:
	case NF_DROP:
		break;
	default:
		printk(KERN_ERR KBUILD_MODNAME ": invalid return code %u\n",
		       info->unavail_retcode);
		return INVAL_RET;
	}

	switch (info->unacct_retcode) {
	case XT_CONTINUE:
	case NF_ACCEPT:
	case NF_DROP:
		break;
	default:
		printk(KERN_ERR KBUILD_MODNAME ": invalid return code %u\n",
		       info->unacct_retcode);
		return INVAL_RET;
	}

	switch (info->retcode) {
	case XT_CONTINUE:
	case NF_ACCEPT:
	case NF_DROP:
		break;
	default:
		printk(KERN_ERR KBUILD_MODNAME ": invalid return code %u\n",
		       info->retcode);
		return INVAL_RET;
	}

	kdata = kzalloc(sizeof (struct xt_acct_target_kdata), GFP_KERNEL);

	if (!kdata) {
		printk(KERN_ERR KBUILD_MODNAME
		       ": cannot allocate target kernel data\n");
		return NOMEM_RET;
	}

#define MASK32(bits) htonl((u32) 0xFFFFFFFF << (32 - (bits)))

	if (info->aggr_by & XT_ACCT_AGGR_SRC) {
#if IPT_ACCT
		kdata->smask = MASK32(info->smask);
#else
		if (info->smask == 128)
			;
		else if (info->smask >= 96)
			kdata->smask = MASK32(info->smask - 96);
		else if (info->smask >= 64)
			kdata->smask = MASK32(info->smask - 64);
		else if (info->smask >= 32)
			kdata->smask = MASK32(info->smask - 32);
#endif
	}

	if (info->aggr_by & XT_ACCT_AGGR_DST) {
#if IPT_ACCT
		kdata->dmask = MASK32(info->dmask);
#else
		if (info->dmask == 128)
			;
		else if (info->dmask >= 96)
			kdata->dmask = MASK32(info->dmask - 96);
		else if (info->dmask >= 64)
			kdata->dmask = MASK32(info->dmask - 64);
		else if (info->dmask >= 32)
			kdata->dmask = MASK32(info->dmask - 32);
#endif
	}

#undef MASK32

	info->kdata = kdata;
	ref = xt_acct_pool_ref_create(info->pool_id, NULL, kdata, NULL);

	if (!ref) {
		kfree(kdata);
		return NOMEM_RET;
	}

	return SUCCESS_RET;

#undef NOMEM_RET
#undef INVAL_RET
#undef SUCCESS_RET
}

static void xt_acct_target_destroy(
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
		const struct xt_target *target,
		void *target_info
# if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
		, unsigned int target_info_size
# endif
#else
		const struct xt_tgdtor_param *param
#endif
		)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 28)
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) target_info;
#else
	struct xt_acct_target_info *info =
		(struct xt_acct_target_info *) param->targinfo;
#endif
	struct xt_acct_target_kdata *kdata = info->kdata;
	struct xt_acct_pool_ref *ref = kdata->pool_ref;

	spin_lock_bh(&ref->targets_lock);
	list_del(&kdata->list_node);
	spin_unlock_bh(&ref->targets_lock);

	kfree(kdata);

	xt_acct_pool_ref_put(ref);
}

static void xt_acct_pool_timer(unsigned long data)
{
	struct xt_acct_pool *pool = (struct xt_acct_pool *) data;
	unsigned long ts = get_seconds();

	if (atomic_read(&pool->timer_flag)) {
		init_timer(&pool->timer);
		pool->timer.function = xt_acct_pool_timer;
		pool->timer.data = data;
		pool->timer.expires += (pool->cfg.interval
					- ts % pool->cfg.interval) * HZ;
		add_timer(&pool->timer);
	}

	wake_up(&pool->ref->wq);
}

static int xt_acct_proc_open(struct inode *inode, struct file *file)
{
	struct xt_acct_proc_pdata *pdata;
       
	pdata = kzalloc(sizeof(struct xt_acct_proc_pdata), GFP_KERNEL);

	if (!pdata)
		return -ENOMEM;

	rwlock_init(&pdata->setup_lock);

	file->private_data = pdata;
	return 0;
}

static ssize_t xt_acct_proc_read(struct file *file, char __user *buf,
				 size_t size, loff_t *offset)
{
	struct xt_acct_proc_pdata *pdata = file->private_data;
	struct xt_acct_pool_ref *ref;
	struct xt_acct_pool *pool;
	struct xt_acct_record *ready_record;
	bool ready = false;
	size_t ready_cnt, nread;
	size_t size1, size2;
	ssize_t ret = 0;

	read_lock_bh(&pdata->setup_lock);
	ref = pdata->pool_ref;
	read_unlock_bh(&pdata->setup_lock);

	if (!ref)
		return -EINVAL;

	size -= size % sizeof(struct xt_acct_record);

	if (size == 0)
		return 0;

retry:
	pool = xt_acct_pool_ref_deref(ref);

	if (!pool)
		goto wait;

	if (!xt_acct_pool_data_get(pool))
		goto unlock_pool;

	if (!spin_trylock(&pool->read_lock))
		goto unlock_data;

	if (pool->cfg.interval > 0) {
		spin_lock_bh(&pool->acct_lock);
		ready_cnt = xt_acct_pool_ready_used(pool, 0);
		spin_unlock_bh(&pool->acct_lock);
	} else {
		spin_lock_bh(&pool->ready_ptr_lock);
		ready_cnt = pool->ready_cnt;
		spin_unlock_bh(&pool->ready_ptr_lock);
	}

	if (ready_cnt == 0)
		goto unlock_reading;

	/*
	 * We can use pool->ready_record safely even without holding
	 * pool->ready_ptr_lock, because it can only change when
	 * pool->ready_cnt is zero, and its decreasing is guarded
	 * by pool->read_lock which we now hold.
	 */

	size1 = pool->records_end - pool->ready_record;

	if (ready_cnt > size1)
		size2 = ready_cnt - size1;
	else {
		size1 = ready_cnt;
		size2 = 0;
	}

	size1 *= sizeof(struct xt_acct_record);
	size2 *= sizeof(struct xt_acct_record);

	if (size > size1) {
		if (copy_to_user(buf, pool->ready_record, size1)) {
			ret = -EFAULT;
			goto unlock_reading;
		}

		buf += size1;
		size2 = min(size2, size - size1);

		if (size2 > 0) {
			if (copy_to_user(buf, pool->records, size2)) {
				ret = -EFAULT;
				goto unlock_reading;
			}

			ret = size1 + size2;
			ready_record = (void *) pool->records + size2;
		} else {
			ret = size1;
			ready_record = (void *) pool->ready_record + size1;
		}
	} else {
		if (copy_to_user(buf, pool->ready_record, size)) {
			ret = -EFAULT;
			goto unlock_reading;
		}

		ret = size;
		ready_record = (void *) pool->ready_record + size;
	}

	if (ready_record == pool->records_end)
		ready_record = pool->records;

	nread = ret / sizeof (struct xt_acct_record);

	spin_lock_bh(&pool->acct_lock);
	if (pool->free_cnt == 0)
		pool->free_record = pool->ready_record;
	pool->free_cnt += nread;
	spin_unlock_bh(&pool->acct_lock);

	spin_lock_bh(&pool->ready_ptr_lock);
	pool->ready_cnt -= nread;
	ready = pool->ready_cnt > 0;
	pool->ready_record = ready ? ready_record : NULL;
	spin_unlock_bh(&pool->ready_ptr_lock);

unlock_reading:
	spin_unlock(&pool->read_lock);
unlock_data:
	xt_acct_pool_data_put(pool);
unlock_pool:
	xt_acct_pool_put(pool);

wait:
	if (ret == 0 && size != 0) {
		if (file->f_flags & O_NONBLOCK)
			ret = -EAGAIN;
		else {
			int flag = 0;
			if (wait_event_interruptible(ref->wq, flag++))
				return -ERESTARTSYS;
			goto retry;
		}
	} else if (ready)
		wake_up(&ref->wq);

	return ret;
}

unsigned int xt_acct_proc_poll(struct file *file,
                               struct poll_table_struct *pt)
{
	struct xt_acct_proc_pdata *pdata = file->private_data;
	struct xt_acct_pool_ref *ref;
	struct xt_acct_pool *pool;
	unsigned int ret = 0;

	read_lock_bh(&pdata->setup_lock);
	ref = pdata->pool_ref;
	read_unlock_bh(&pdata->setup_lock);

	if (!ref)
		return POLLERR;

	pool = xt_acct_pool_ref_deref(ref);

	if (!pool)
		goto register_wq;
	
	if (!xt_acct_pool_data_get(pool))
		goto unlock_pool;

	if (pool->cfg.interval > 0) {
		spin_lock_bh(&pool->acct_lock);
		if (xt_acct_pool_ready_used(pool, 0) > 0)
			ret = POLLIN | POLLRDNORM;
		spin_unlock_bh(&pool->acct_lock);
	} else {
		spin_lock_bh(&pool->ready_ptr_lock);
		if (pool->ready_record)
			ret = POLLIN | POLLRDNORM;
		spin_unlock_bh(&pool->ready_ptr_lock);
	}

	xt_acct_pool_data_put(pool);
unlock_pool:
	xt_acct_pool_put(pool);

register_wq:
  	poll_wait(file, &ref->wq, pt);
	return ret;
}

static long xt_acct_proc_ioctl (struct file *file, unsigned int cmd,
                                unsigned long data)
{
	struct xt_acct_proc_pdata *pdata = file->private_data;
	struct xt_acct_pool_ref *ref;

	switch (cmd) {
	case XT_ACCT_IOCTL_SETUP:
		if (data > 0xFFFF)
			return -EINVAL;

		write_lock_bh(&pdata->setup_lock);

		if (pdata->pool_ref) {
			write_unlock_bh(&pdata->setup_lock);
			return -EEXIST;
		}

		ref = xt_acct_pool_ref_create((u16) data, NULL, NULL, pdata);

		if (!ref) {
			write_unlock_bh(&pdata->setup_lock);
			return -ENOMEM;
		}

		write_unlock_bh(&pdata->setup_lock);
		return 0;
	default:
		return -EINVAL;
	}
}

static int xt_acct_proc_release(struct inode *inode, struct file *file)
{
	struct xt_acct_proc_pdata *pdata = file->private_data;
	struct xt_acct_pool_ref *ref = pdata->pool_ref;

	if (ref) {
		spin_lock_bh(&ref->files_lock);
		list_del(&pdata->list_node);
		spin_unlock_bh(&ref->files_lock);

		xt_acct_pool_ref_put(ref);
	}

	kfree(pdata);
	return 0;
}

static int parse_decimal(const char *str, size_t size, unsigned long *result,
                         unsigned long min_value, unsigned long max_value,
			 bool allow_newline)
{
	unsigned long add, value = 0;

	if (size == 0 || *str < '0' || *str > '9')
		return -EINVAL;

	do {
		add = *str - '0';

		if (value > ULONG_MAX / 10
		    || (value == ULONG_MAX / 10 && add > ULONG_MAX % 10))
			return -EINVAL;

		value = value * 10 + add;

		if (value > max_value)
			return -EINVAL;

		str += 1;
		size -= 1;
	} while (size > 0 && *str >= '0' && *str <= '9');

	if (size > 0 && *str && (!allow_newline || *str != '\n'))
		return -EINVAL;

	if (value < min_value)
		return -EINVAL;

	*result = value;
	return 0;
}

static ssize_t show_enabled(struct xt_acct_pool *pool, char *buf)
{
	bool dead;
	bool enabled;

	spin_lock_bh(&pool->state_lock);
	dead = pool->state == STATE_DEAD;
	enabled = pool->state >= STATE_ENABLED;
	spin_unlock_bh(&pool->state_lock);

	if (dead)
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, enabled ? "1\n" : "0\n");
}

static ssize_t store_enabled(struct xt_acct_pool *pool, const char *buf,
                             size_t size)
{
	unsigned long enabled;
	unsigned int hashtab_size, i;
	int state;
	ssize_t ret = size;
	
	if (parse_decimal(buf, size, &enabled, 0, 1, true) < 0)
		return -EINVAL;

retry:
	spin_lock_bh(&pool->state_lock);

	if (enabled) {
		if (pool->state >= STATE_ENABLED) {
			spin_unlock_bh(&pool->state_lock);
			return size;
		} else if (pool->state == STATE_DISABLED) {
			pool->state = STATE_ENABLING;
		} else if (pool->state == STATE_DEAD) {
			spin_unlock_bh(&pool->state_lock);
			return -ENOENT;
		} else {
			spin_unlock_bh(&pool->state_lock);
			goto retry;
		}
	} else {
		if (pool->state == STATE_ENABLED) {
			pool->state = STATE_DISABLING;
		} else if (pool->state > STATE_ENABLED) {
			pool->disabling_pending = true;
			spin_unlock_bh(&pool->state_lock);
			goto retry;
		} else if (pool->state == STATE_DISABLED) {
			spin_unlock_bh(&pool->state_lock);
			return size;
		} else if (pool->state == STATE_DEAD) {
			spin_unlock_bh(&pool->state_lock);
			return -ENOENT;
		} else {
			spin_unlock_bh(&pool->state_lock);
			goto retry;
		}
	}

	spin_unlock_bh(&pool->state_lock);

	state = STATE_DISABLED;

	if (enabled) {
		pool->records = vmalloc(sizeof(struct xt_acct_record)
		                        * pool->cfg.size);

		if (!pool->records) {
			ret = -ENOMEM;
			goto update_state;
		}

		if (pool->cfg.interval > 0) {
			pool->lists = vmalloc(
			                sizeof(struct xt_acct_records_list)
		                        * pool->cfg.size);

			if (!pool->lists) {
				vfree(pool->records);
				ret = -ENOMEM;
				goto update_state;
			}

			hashtab_size = pool->cfg.size / 2;

			for (i = 0; i < ARRAY_SIZE(primes); ++i) {
				if (primes[i] > hashtab_size) {
					if (i == 0)
						hashtab_size = primes[0];
					else
						hashtab_size = primes[i - 1];
					break;
				}
			}

			if (i == ARRAY_SIZE(primes))
				hashtab_size = primes[i - 1];

			pool->hashtab = vmalloc(
			                  sizeof(struct xt_acct_hash_bucket)
		                          * hashtab_size);
			pool->hashtab_size = hashtab_size;

			if (!pool->hashtab) {
				vfree(pool->records);
				vfree(pool->lists);
				ret = -ENOMEM;
				goto update_state;
			}

			memset(pool->hashtab, 0,
			       sizeof(struct xt_acct_hash_bucket)
			       * hashtab_size);
		} else {
			pool->lists = NULL;
			pool->hashtab = NULL;
		}

		pool->records_end = pool->records + pool->cfg.size;
		pool->free_record = pool->records;
		pool->free_cnt = pool->cfg.size;
		pool->ready_record = NULL;
		pool->ready_cnt = 0;
		pool->used_record = NULL;
		pool->used_cnt = 0;

		pool->last_ts = 0;

		pool->stat.enabled_ts = get_seconds();
		pool->stat.pkts_acct = 0;
		pool->stat.bytes_acct = 0;
		pool->stat.pkts_not_acct = 0;
		pool->stat.bytes_not_acct = 0;

		state = STATE_ENABLED;

		if (pool->cfg.interval > 0) {
			atomic_set(&pool->timer_flag, 1);
			init_timer(&pool->timer);
			pool->timer.function = xt_acct_pool_timer;
			pool->timer.data = (unsigned long) pool;
			mod_timer(&pool->timer, round_jiffies(jiffies + HZ));
		}
	} else {
		vfree(pool->hashtab);
		vfree(pool->lists);
		vfree(pool->records);

		if (pool->cfg.interval > 0) {
			atomic_set(&pool->timer_flag, 0);
			del_timer_sync(&pool->timer);
		}
	}

update_state:
	spin_lock_bh(&pool->state_lock);
	pool->state = state;
	spin_unlock_bh(&pool->state_lock);

	return ret;
}

static ssize_t show_ro_mode(struct xt_acct_pool *pool, char *buf)
{
	bool dead;
	bool ro_mode;

	spin_lock_bh(&pool->state_lock);
	dead = pool->state == STATE_DEAD;
	if (!dead)
		ro_mode = atomic_read(&pool->cfg.ro_mode);
	spin_unlock_bh(&pool->state_lock);

	if (dead)
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, ro_mode ? "1\n" : "0\n");
}

static ssize_t store_ro_mode(struct xt_acct_pool *pool,
                                 const char *buf, size_t size)
{
	unsigned long value;
	ssize_t ret = size;

	if (parse_decimal(buf, size, &value, 0, 1, true) < 0)
		return -EINVAL;

	spin_lock_bh(&pool->state_lock);

	if (pool->state == STATE_DEAD)
		ret = -ENOENT;
	else
		atomic_set(&pool->cfg.ro_mode, (unsigned int) value);

	spin_unlock_bh(&pool->state_lock);

	return ret;
}

static ssize_t show_size(struct xt_acct_pool *pool, char *buf)
{
	bool dead;
	unsigned int size;

	spin_lock_bh(&pool->state_lock);
	dead = pool->state == STATE_DEAD;
	size = pool->cfg.size;
	spin_unlock_bh(&pool->state_lock);

	if (dead)
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, "%u\n", size);
}

static ssize_t store_size(struct xt_acct_pool *pool, const char *buf,
                          size_t size)
{
	unsigned long value;
	ssize_t ret = size;

	if (parse_decimal(buf, size, &value, 0, UINT_MAX, true) < 0)
		return -EINVAL;

	if (value == 0)
		value = XT_ACCT_DEFAULT_SIZE;

	spin_lock_bh(&pool->state_lock);

	if (pool->state == STATE_DISABLED
	    || pool->state == STATE_DISABLING)
		pool->cfg.size = value;
	else if (pool->state == STATE_DEAD)
		ret = -ENOENT;
	else
		ret = -EBUSY;

	spin_unlock_bh(&pool->state_lock);

	return ret;
}

static ssize_t show_interval(struct xt_acct_pool *pool, char *buf)
{
	bool dead;
	unsigned int interval;

	spin_lock_bh(&pool->state_lock);
	dead = pool->state == STATE_DEAD;
	interval = pool->cfg.interval;
	spin_unlock_bh(&pool->state_lock);

	if (dead)
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, "%u\n", interval);
}

static ssize_t store_interval(struct xt_acct_pool *pool, const char *buf,
                              size_t size)
{
	unsigned long value;
	ssize_t ret = size;

	if (parse_decimal(buf, size, &value, 0, 60, true) < 0)
		return -EINVAL;

	if (value > 0 && 60 % value != 0)
		return -EINVAL;

	spin_lock_bh(&pool->state_lock);

	if (pool->state == STATE_DISABLED
	    || pool->state == STATE_DISABLING)
		pool->cfg.interval = value;
	else if (pool->state == STATE_DEAD)
		ret = -ENOENT;
	else
		ret = -EBUSY;

	spin_unlock_bh(&pool->state_lock);

	return ret;
}

static ssize_t show_stat(struct xt_acct_pool *pool, char *buf)
{
	struct xt_acct_stat stat;

	spin_lock_bh(&pool->state_lock);

	if (pool->state == STATE_ENABLED)
		pool->state += 1;
	else if (pool->state == STATE_DEAD) {
		spin_unlock_bh(&pool->state_lock);
		return -ENOENT;
	} else {
		spin_unlock_bh(&pool->state_lock);
		return -ENODATA;
	}

	spin_unlock_bh(&pool->state_lock);

	spin_lock_bh(&pool->stat_lock);
	stat.enabled_ts = pool->stat.enabled_ts;
	stat.pkts_acct = pool->stat.pkts_acct;
	stat.bytes_acct = pool->stat.bytes_acct;
	stat.pkts_not_acct = pool->stat.pkts_not_acct;
	stat.bytes_not_acct = pool->stat.bytes_not_acct;
	spin_unlock_bh(&pool->stat_lock);

	spin_lock_bh(&pool->state_lock);
	pool->state -= 1;
	spin_unlock_bh(&pool->state_lock);

	memcpy(buf, &stat, sizeof(stat));

	return sizeof (stat);
}

struct xt_acct_cfg_pool_attr {
	struct  configfs_attribute attr;
	ssize_t (*show)(struct xt_acct_pool *pool, char *buf);
	ssize_t (*store)(struct xt_acct_pool *pool, const char *buf,
	                 size_t size);
};

#define XT_ACCT_POOL_ATTR(attr) \
	(container_of(attr, struct xt_acct_cfg_pool_attr, attr))

#ifndef __CONFIGFS_ATTR
# define __CONFIGFS_ATTR(_name,_mode,_show,_store)                     \
{                                                                      \
        .attr   = {                                                    \
		.ca_name = __stringify(_name),                         \
		.ca_mode = _mode,                                      \
		.ca_owner = THIS_MODULE,                               \
	},                                                             \
	.show   = _show,                                               \
	.store  = _store,                                              \
}
#endif

#define XT_ACCT_POOL_ATTR_RW(_name)                                    \
static struct xt_acct_cfg_pool_attr xt_acct_cfg_pool_attr_##_name =    \
	__CONFIGFS_ATTR(_name, S_IRUGO | S_IWUSR,                      \
	                show_##_name, store_##_name)
#define XT_ACCT_POOL_ATTR_RO(_name)                                    \
static struct xt_acct_cfg_pool_attr xt_acct_cfg_pool_attr_##_name =    \
	__CONFIGFS_ATTR(_name, S_IRUGO, show_##_name, NULL)

XT_ACCT_POOL_ATTR_RW(enabled);
XT_ACCT_POOL_ATTR_RW(size);
XT_ACCT_POOL_ATTR_RW(interval);
XT_ACCT_POOL_ATTR_RW(ro_mode);
XT_ACCT_POOL_ATTR_RO(stat);

static struct configfs_attribute *xt_acct_cfg_pool_attrs[] = {
	&xt_acct_cfg_pool_attr_enabled.attr,
	&xt_acct_cfg_pool_attr_ro_mode.attr,
	&xt_acct_cfg_pool_attr_size.attr,
	&xt_acct_cfg_pool_attr_interval.attr,
	&xt_acct_cfg_pool_attr_stat.attr,
	NULL
};

static void xt_acct_cfg_pool_release(struct config_item *item)
{
	xt_acct_pool_put(XT_ACCT_POOL(item));
};

static ssize_t xt_acct_cfg_pool_show_attr(struct config_item *item,
                                          struct configfs_attribute *attr,
                                          char *buf)
{
	struct xt_acct_pool *pool = XT_ACCT_POOL(item);
	return XT_ACCT_POOL_ATTR(attr)->show(pool, buf);
}

static ssize_t xt_acct_cfg_pool_store_attr(struct config_item *item,
                                           struct configfs_attribute *attr,
                                           const char *buf, size_t size)
{
	struct xt_acct_pool *pool = XT_ACCT_POOL(item);
	return XT_ACCT_POOL_ATTR(attr)->store(pool, buf, size);
}

static struct configfs_item_operations xt_acct_cfg_pool_item_ops = {
	.release         = xt_acct_cfg_pool_release,
	.show_attribute  = xt_acct_cfg_pool_show_attr,
	.store_attribute = xt_acct_cfg_pool_store_attr
};

static struct config_item_type xt_acct_cfg_pool_item_type = {
	.ct_item_ops     = &xt_acct_cfg_pool_item_ops,
	.ct_attrs        = xt_acct_cfg_pool_attrs,
	.ct_owner        = THIS_MODULE
};

static struct config_item *xt_acct_cfg_pool_create(struct config_group *group,
                                                   const char *name)
{
	struct xt_acct_pool *pool;
	struct xt_acct_pool_ref *ref;
	unsigned long pool_id;

	if (parse_decimal(name, strlen(name), &pool_id, 0, 0xFFFF, false) < 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
		return NULL;
#else
		return ERR_PTR(-EINVAL);
#endif

	pool = kzalloc(sizeof(struct xt_acct_pool), GFP_KERNEL);

	if (!pool)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
		return NULL;
#else
		return ERR_PTR(-ENOMEM);
#endif

	pool->id = pool_id;
	pool->cfg.size = XT_ACCT_DEFAULT_SIZE;
	pool->cfg.interval = XT_ACCT_DEFAULT_INTERVAL;
	atomic_set(&pool->cfg.ro_mode, 0);

	kref_init(&pool->refs_cnt);
	spin_lock_init(&pool->state_lock);
	spin_lock_init(&pool->stat_lock);
	spin_lock_init(&pool->ready_ptr_lock);
	spin_lock_init(&pool->read_lock);
	spin_lock_init(&pool->acct_lock);
	config_item_init_type_name(&pool->cfg_item, name,
	                           &xt_acct_cfg_pool_item_type);

	ref = xt_acct_pool_ref_create(pool_id, pool, NULL, NULL);

	if (IS_ERR(ref)) {
		kfree(pool);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
		return NULL;
#else
		return (struct config_item *) ref;
#endif
	}

	return &pool->cfg_item;
}

static void xt_acct_cfg_pool_drop(struct config_group *group,
                                  struct config_item *item)
{
	struct xt_acct_pool *pool = XT_ACCT_POOL(item);
	struct xt_acct_pool_ref *ref = pool->ref;
	bool enabled = false;

	spin_lock_bh(&ref->pool_lock);
	ref->pool = NULL;
	spin_unlock_bh(&ref->pool_lock);

retry:
	spin_lock_bh(&pool->state_lock);

	if (pool->state == STATE_ENABLED) {
		enabled = true;
		pool->state = STATE_DEAD;
	} else if (pool->state > STATE_ENABLED) {
		pool->disabling_pending = true;
		spin_unlock_bh(&pool->state_lock);
		goto retry;
	} else if (pool->state == STATE_DISABLED) {
		pool->state = STATE_DEAD;
	} else {
		spin_unlock_bh(&pool->state_lock);
		goto retry;
	}

	spin_unlock_bh(&pool->state_lock);

	if (enabled) {
		vfree(pool->hashtab);
		vfree(pool->lists);
		vfree(pool->records);

		if (pool->cfg.interval > 0) {
			atomic_set(&pool->timer_flag, 0);
			del_timer_sync(&pool->timer);
		}
	}

	pool->ref = NULL;
	xt_acct_pool_ref_put(ref);

	config_item_put(&pool->cfg_item);
}

static struct configfs_group_operations xt_acct_cfg_subsys_group_ops = {
	.make_item    = xt_acct_cfg_pool_create,
	.drop_item    = xt_acct_cfg_pool_drop
};

static struct config_item_type xt_acct_cfg_subsys_type = {
	.ct_group_ops = &xt_acct_cfg_subsys_group_ops,
	.ct_owner     = THIS_MODULE
};

static struct configfs_subsystem xt_acct_cfg_subsys = {
	.su_group     = {
		.cg_item = {
			.ci_namebuf = XT_ACCT_NAME,
			.ci_type    = &xt_acct_cfg_subsys_type
		}
	}
};

static struct proc_dir_entry *xt_acct_proc_entry;

static struct file_operations xt_acct_proc_fops __read_mostly = {
	.open           = xt_acct_proc_open,
	.read           = xt_acct_proc_read,
	.poll           = xt_acct_proc_poll,
	.unlocked_ioctl = xt_acct_proc_ioctl,
	.release        = xt_acct_proc_release,
	.owner          = THIS_MODULE
};

static struct xt_target xt_acct_target __read_mostly = {
	.name         = "ACCT",
#if IPT_ACCT
	.family       = AF_INET,
#else
	.family       = AF_INET6, 
#endif
	.target       = xt_acct_target_handle,
	.checkentry   = xt_acct_target_check,
	.destroy      = xt_acct_target_destroy,
	.targetsize   = sizeof(struct xt_acct_target_info),
	.me           = THIS_MODULE
};

static int __init xt_acct_init(void)
{
	int ret = xt_register_target(&xt_acct_target);

	if (ret != 0)
		return ret;

	xt_acct_proc_entry = proc_create(XT_ACCT_NAME, S_IRUSR | S_IRGRP,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	                                 proc_net,
#else
	                                 init_net.proc_net,
#endif
	                                 &xt_acct_proc_fops);

	if (!xt_acct_proc_entry) {
		ret = -ENOMEM;
		goto unregister_target;
	}

	config_group_init(&xt_acct_cfg_subsys.su_group);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
	init_MUTEX(&xt_acct_cfg_subsys.su_sem);
#else
	mutex_init(&xt_acct_cfg_subsys.su_mutex);
#endif

	ret = configfs_register_subsystem(&xt_acct_cfg_subsys);

	if (ret != 0)
		goto unregister_proc;

#ifdef XT_ACCT_CT
	need_conntrack();
#endif
	return 0;

unregister_proc:
	remove_proc_entry(xt_acct_proc_entry->name,
	                  xt_acct_proc_entry->parent);
unregister_target:
	xt_unregister_target(&xt_acct_target);
	return ret;
}

static void __exit xt_acct_exit(void)
{
	configfs_unregister_subsystem(&xt_acct_cfg_subsys);
	remove_proc_entry(xt_acct_proc_entry->name,
	                  xt_acct_proc_entry->parent);
	xt_unregister_target(&xt_acct_target);
}

module_init(xt_acct_init);
module_exit(xt_acct_exit);

