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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#define IPT_ACCT @IPT_ACCT@
#define IP6T_ACCT (!@IPT_ACCT@)

#if IPT_ACCT
# define IP_MASK_MAX 32
#else
# define IP_MASK_MAX 128
#endif

#ifdef IPTABLES14PLUS
# include <xtables.h>
# ifndef XTABLES_VERSION
#   define XTABLES_VERSION "1.4.0"
# endif
# define ERROR xtables_error
# define REGISTER_TARGET xtables_register_target
#else
# if IPT_ACCT
#   include <iptables.h>
#   define xt_ip ipt_ip
#   define xt_entry ipt_entry
#   define xt_entry_target ipt_entry_target
#   define xtables_target iptables_target
#   define REGISTER_TARGET register_target
# else
#   include <ip6tables.h>
#   define xt_ip ip6t_ip6
#   define xt_entry ip6t_entry
#   define xt_entry_target ip6t_entry_target
#   define xtables_target ip6tables_target
#   define REGISTER_TARGET register_target6
# endif
# define XTABLES_VERSION IPTABLES_VERSION
# define ERROR exit_error
#endif

#include "nf_xt_ACCT.h"

#define XT_ACCT_AGGR_DEFAULT (XT_ACCT_AGGR_SRC | XT_ACCT_AGGR_DST \
                              | XT_ACCT_AGGR_SPORT | XT_ACCT_AGGR_DPORT \
                              | XT_ACCT_AGGR_PROTO)

static struct option extra_opts[] =
{
  { "pool", 1, 0, '1' },
  { "tag", 1, 0, '2' },
  { "aggr-by", 1, 0, '3' },
  { "master_src", 0, 0, '4' },
  { "add-llh-size", 0, 0, '5' },
  { "when-unavailable", 0, 0, '6' },
  { "when-unaccounted", 0, 0, '7' },
  { "continue", 0, 0, '8' },
  { "accept", 0, 0, '9' },
  { "drop", 0, 0, 'A' },
  { 0, 0, 0, 0 }
};

static void
xt_acct_help ()
{
  printf ("\
ACCT v%s target options:\n\
  --pool ID       Use the accounting pool #ID.\n\
  --tag N         Aggregate matching packets with tag N (defaults to 0).\n\
  --aggr-by SPEC  Set the fields used for aggregation. SPEC must be\n\
                  a comma-separated list of the following tokens:\n\
                    src[/MASK] - Source address.\n\
                    dst[/MASK] - Destination address.\n\
                    sport      - Source port.\n\
                    dport      - Destination port.\n\
                    proto      - Protocol number.\n\
                    conn       - Connection mark value.\n\
                  Default is 'src,dst,sport,dport,proto'.\n\
  --master-src    If the master connection has the same destination but\n\
                  a different source, use it.\n\
  --add-llh-size  Add link layer header size to packet size.\n\
  --when-unavailable ACTION\n\
                  What to do with packets when the pool doesn't exist or is\n\
                  disabled or entered the read-only mode.\n\
                  ACTION must be one of:\n\
                    continue   - Return packets to the firewall.\n\
                    accept     - Accept packets.\n\
                    drop       - Drop packets.\n\
                  Default is to do the same action we do after a packet is\n\
                  accounted.\n\
  --when-unaccounted ACTION\n\
                  What to do with the packets that couldn't be accounted\n\
                  due to pool buffer overrun. ACTION must be one of:\n\
                    continue   - Return packets to the firewall.\n\
                    accept     - Accept packets.\n\
                    drop       - Drop packets.\n\
                  Default is to do the same action we do after a packet is\n\
                  accounted.\n\
  --continue      Return packets to the firewall after accounting (default).\n\
  --accept        Accept packets after accounting.\n\
  --drop          Drop packets after accounting.\n\n", PACKAGE_VERSION);
}

static void
xt_acct_init (struct xt_entry_target *target
#ifndef IPTABLES14PLUS
              , unsigned int *nfcache
#endif
              )
{
  struct xt_acct_target_info *info
    = (struct xt_acct_target_info *) target->data;

  info->tag = 0;
  info->aggr_by = XT_ACCT_AGGR_DEFAULT;
  info->smask = IP_MASK_MAX;
  info->dmask = IP_MASK_MAX;
  info->master_src = 0;
  info->add_llh_size = 0;
  info->unavail_retcode = NF_MAX_VERDICT + 1;
  info->unacct_retcode = NF_MAX_VERDICT + 1;
  info->retcode = XT_CONTINUE;
}

static int
xt_acct_parse (int c, char **argv, int invert, unsigned int *flags,
#ifdef IPTABLES14PLUS
               const void *entry,
#else
               const struct xt_entry *entry,
#endif
               struct xt_entry_target **target)
{
  struct xt_acct_target_info *info
    = (struct xt_acct_target_info *) (*target)->data;
  const char *s;
  char *end;
  unsigned long int_value;
  int error_p;

  switch (c)
    {
    case '1': /* --pool ID */
      errno = 0;
      int_value = strtoul (optarg, &end, 10);

      if (errno != 0 || *end || *optarg == '-' || int_value > 0xFFFF)
        ERROR (PARAMETER_PROBLEM,
               "Pool number must be between 0 and 65535");

      info->pool_id = (uint16_t) int_value;
      *flags = 1;
      break;
    case '2': /* --tag N */
      errno = 0;
      int_value = strtoul (optarg, &end, 10);

      if (errno != 0 || *end || *optarg == '-' || int_value > 0xFFFFFFFF)
        ERROR (PARAMETER_PROBLEM,
               "Pool number must be between 0 and %u", 0xFFFFFFFF);

      info->tag = (uint32_t) int_value;
      break;
    case '3': /* --aggr-by SPEC */
      s = optarg;
      error_p = 0;

      while (*s) {
          if (!strncmp(s, "src", 3))
            {
              s += 3;
              int_value = 0;

              if (*s == '/')
                {
                  s += 1;

                  if (*s < '0' || *s > '9')
                    {
                      error_p = 1;
                      break;
                    }

                  do
                    {
                      int_value = int_value * 10 + (*s - '0');

                      if (int_value > IP_MASK_MAX)
                        {
                          error_p = 1;
                          break;
                        }

                      s += 1;
                    } while (*s >= '0' && *s <= '9');

                  if (error_p)
                    break;

                  info->smask = int_value;
                }
              else
                info->smask = IP_MASK_MAX;

              info->aggr_by |= XT_ACCT_AGGR_SRC;
            }
          else if (!strncmp (s, "dst", 3))
            {
              s += 3;
              int_value = 0;

              if (*s == '/')
                {
                  s += 1;

                  if (*s < '0' || *s > '9')
                    {
                      error_p = 1;
                      break;
                    }

                  do
                    {
                      int_value = int_value * 10 + (*s - '0');

                      if (int_value > IP_MASK_MAX)
                        {
                          error_p = 1;
                          break;
                        }

                      s += 1;
                    } while (*s >= '0' && *s <= '9');

                  if (error_p)
                    break;

                  info->dmask = int_value;
                }
              else
                info->dmask = IP_MASK_MAX;

              info->aggr_by |= XT_ACCT_AGGR_DST;
            }
          else if (!strncmp (s, "sport", 5))
            info->aggr_by |= XT_ACCT_AGGR_SPORT;
          else if (!strncmp (s, "dport", 5))
            info->aggr_by |= XT_ACCT_AGGR_DPORT;
          else if (!strncmp (s, "proto", 5))
            info->aggr_by |= XT_ACCT_AGGR_PROTO;
          else if (!strncmp (s, "conn", 4))
            info->aggr_by |= XT_ACCT_AGGR_CONN;

          if (!*s)
            break;

          if (*s == ',')
            {
              s += 1;

              if (!*s)
                {
                  error_p = 1;
                  break;
                }
            }
          else
            {
              error_p = 1;
              break;
            }
      }

      if (error_p)
        ERROR (PARAMETER_PROBLEM, "Invalid aggregation spec `%s'", optarg);

      break;
    case '4': /* --master-src */
      info->master_src = 1;
      break;
    case '5': /* --add-llh-size */
      info->add_llh_size = 1;
      break;
    case '6': /* --when-unavailable */
      if (!strcmp (optarg, "continue"))
        info->unavail_retcode = XT_CONTINUE;
      else if (!strcmp (optarg, "accept"))
        info->unavail_retcode = NF_ACCEPT;
      else if (!strcmp (optarg, "drop"))
        info->unavail_retcode = NF_DROP;
      else
        ERROR (PARAMETER_PROBLEM, "Invalid action `%s'", optarg);
      break;
    case '7': /* --when-unaccounted */
      if (!strcmp (optarg, "continue"))
        info->unacct_retcode = XT_CONTINUE;
      else if (!strcmp (optarg, "accept"))
        info->unacct_retcode = NF_ACCEPT;
      else if (!strcmp (optarg, "drop"))
        info->unacct_retcode = NF_DROP;
      else
        ERROR (PARAMETER_PROBLEM, "Invalid action `%s'", optarg);
      break;
    case '8': /* --continue */
      info->retcode = XT_CONTINUE;
      break;
    case '9': /* --accept */
      info->retcode = NF_ACCEPT;
      break;
    case 'A': /* --drop */
      info->retcode = NF_DROP;
      break;
    default:
      return 0;
    }

  if (info->unavail_retcode == NF_MAX_VERDICT + 1)
    info->unavail_retcode = info->retcode;

  if (info->unacct_retcode == NF_MAX_VERDICT + 1)
    info->unacct_retcode = info->retcode;

  return 1;
}

static void
xt_acct_final_check (unsigned int flags)
{
  if (!flags)
    ERROR (PARAMETER_PROBLEM, "You must specify --pool");
}

static void
xt_acct_print (
#ifdef IPTABLES14PLUS
               const void *ip,
#else
               const struct xt_ip *ip,
#endif
               const struct xt_entry_target *target,
               int numeric_p)
{
  struct xt_acct_target_info *info =
    (struct xt_acct_target_info *) target->data;

  printf ("ACCT to pool %u and ", info->pool_id);

  if (info->retcode == NF_ACCEPT)
    printf ("accept");
  else if (info->retcode == NF_DROP)
    printf ("drop");
  else
    printf ("continue");
}

static void
xt_acct_save (
#ifdef IPTABLES14PLUS
               const void *ip,
#else
               const struct xt_ip *ip,
#endif
               const struct xt_entry_target *target)
{
  struct xt_acct_target_info *info =
    (struct xt_acct_target_info *) target->data;

  printf ("--pool %u ", info->pool_id);

  if (info->tag != 0)
    printf ("--tag %u ", info->tag);

  if (info->aggr_by != XT_ACCT_AGGR_DEFAULT
      || info->smask != IP_MASK_MAX || info->dmask != IP_MASK_MAX)
    {
      if (info->aggr_by == 0)
        printf ("--aggr-by '' ");
      else
        {
          char c = ' ';
          printf ("--aggr-by");

          if (info->aggr_by & XT_ACCT_AGGR_SRC)
            {
              printf ("%csrc/%u", c, info->smask);
              c = ',';
            }

          if (info->aggr_by & XT_ACCT_AGGR_DST)
            {
              printf ("%cdst/%u", c, info->dmask);
              c = ',';
            }

          if (info->aggr_by & XT_ACCT_AGGR_SPORT)
            {
              printf ("%csport", c);
              c = ',';
            }

          if (info->aggr_by & XT_ACCT_AGGR_DPORT)
            {
              printf ("%cdport", c);
              c = ',';
            }

          if (info->aggr_by & XT_ACCT_AGGR_PROTO)
            {
              printf ("%cproto", c);
              c = ',';
            }

          if (info->aggr_by & XT_ACCT_AGGR_CONN)
            {
              printf ("%cconn", c);
              c = ',';
            }

          printf (" ");
        }
    }

  if (info->master_src)
    printf ("--master-src ");

  if (info->add_llh_size)
    printf ("--add-llh-size ");

  if (info->unavail_retcode != info->retcode)
    printf ("--when-unavailable %s",
            info->unavail_retcode == XT_CONTINUE ? "continue"
              : info->unavail_retcode == NF_ACCEPT ? "accept" : "drop");

  if (info->unacct_retcode != info->retcode)
    printf ("--when-unaccounted %s",
            info->unacct_retcode == XT_CONTINUE ? "continue"
              : info->unacct_retcode == NF_ACCEPT ? "accept" : "drop");

  if (info->retcode == NF_ACCEPT)
    printf ("--accept ");
  else if (info->retcode == NF_DROP)
    printf ("--drop ");
}

static struct xtables_target xt_acct_target =
{
  .name = "ACCT",
  .version = XTABLES_VERSION,
  .size = XT_ALIGN (sizeof (struct xt_acct_target_info)),
  .userspacesize = XT_ALIGN (sizeof (struct xt_acct_target_info)),
  .help = &xt_acct_help,
  .init = &xt_acct_init,
  .parse = &xt_acct_parse,
  .final_check = &xt_acct_final_check,
  .print = &xt_acct_print,
  .save = &xt_acct_save,
  .extra_opts = extra_opts
};

void
_init ()
{
  REGISTER_TARGET (&xt_acct_target);
}

