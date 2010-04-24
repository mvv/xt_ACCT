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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "xt_ACCT.h"

#define ARRAY_SIZE(ARRAY) (sizeof (ARRAY) / sizeof ((ARRAY)[0]))

static const char *argv_0;

#define ERROR(MSG,...) \
  fprintf (stderr, "%s: " MSG "\n", argv_0, ## __VA_ARGS__)

static const struct option options[] =
{
  { "ipv4", 0, 0, '4' },
  { "ipv6", 0, 0, '6' },
  { "procfs", 1, 0, 'p' },
  { "configfs", 1, 0, 'c' },
  { "version", 0, 0, 'V' },
  { "help", 0, 0, 'H' },
  { 0, 0, 0, 0 }
};

static const struct option add_options[] =
{
  { "size", 1, 0, 's' },
  { "interval", 1, 0, 'i' },
  { "read-only", 0, 0, 'r' },
  { "read-and-write", 0, 0, 'w' },
  { "enable", 0, 0, 'e' },
  { "no-enable", 0, 0, 'E' },
  { 0, 0, 0, 0 }
};

static const struct option info_options[] =
{
  { "human-readable", 0, 0, 'h' },
  { "columns", 2, 0, 'c' },
  { 0, 0, 0, 0 }
};

static const struct option cfg_options[] =
{
  { "size", 1, 0, 's' },
  { "interval", 1, 0, 'i' },
  { "read-only", 0, 0, 'r' },
  { "read-and-write", 0, 0, 'w' },
  { "enable", 0, 0, 'e' },
  { "no-enable", 0, 0, 'E' },
  { 0, 0, 0, 0 }
};

static const struct option stat_options[] =
{
  { "human-readable", 0, 0, 'h' },
  { "columns", 2, 0, 'c' },
  { 0, 0, 0, 0 }
};

static const struct option read_options[] =
{
  { "follow", 0, 0, 'f' },
  { "no-follow", 0, 0, 'F' },
  { "proto-names", 0, 0, 's' },
  { "proto-numbers", 0, 0, 'd' },
  { 0, 0, 0, 0 }
};

static void
usage ()
{
  printf ("\
Usage: xt_acct_ctl [OPTIONS] [COMMAND]\n\
Options:\n\
  -4, --ipv4\n\
      Connect to the IPv4 kernel module (default).\n\
  -6, --ipv6\n\
      Connect to the IPv6 kernel module.\n\
  --procfs PATH\n\
      Path to procfs mount point (defaults to `/proc').\n\
  --configfs PATH\n\
      Path to configfs mount point (defaults to `/sys/kernel/config').\n\
  --version\n\
      Print the program version and exit.\n\
  --help\n\
      Print this message and exit.\n\
Commands:\n\
  list, ls            - List records pools.\n\
  add  [OPTIONS] POOL - Add a new pool.\n\
    Options:\n\
      -s, --size N\n\
          Pool size in records (defaults to %u).\n\
      -i, --interval N\n\
          Aggregation interval in seconds (defaults to %u).\n\
      -r, --read-only\n\
          Allow to read already acquired data, but prohibit accounting of\n\
          new packets.\n\
      -w, --read-and-write\n\
          Allow both reading of acquired data and accounting of new packets\n\
          (default).\n\
      -e, [-E], --[no-]enable\n\
          Whether to enable the created pool (default is to not enable).\n\
  rm, del        POOL - Remove the pool.\n\
  enable         POOL - Enabled the pool.\n\
  disable        POOL - Disable the pool.\n\
  exists         POOL - Test if the pool exists.\n\
  enabled        POOL - Test if the pool if enabled.\n\
  info [OPTIONS] POOL - Print the pool configuration.\n\
    Options:\n\
      -h, --human-readable\n\
          Print configuration in human readable format (default).\n\
      -c, --columns[=ATTRS]\n\
          Print values of attributes in ATTRS separated by spaces.\n\
          ATTRS defaults to `enabled,ro_mode,size,interval'.\n\
  cfg  [OPTIONS] POOL - Configure the pool.\n\
    Options:\n\
      -s, --size N\n\
          Pool size in records.\n\
      -i, --interval N\n\
          Aggregation interval in seconds.\n\
      -r, --read-only\n\
          Allow to read already acquired data, but prohibit accounting of\n\
          new packets.\n\
      -w, --read-and-write\n\
          Allow both reading of acquired data and accounting of new packets.\n\
      -e, [-E], --[no-]enable\n\
          Whether to enable the configured pool (default is to not enable).\n\
  stat [OPTIONS] POOL - Print the pool counters.\n\
    Options:\n\
      -h, --human-readable\n\
          Print conters in human readable format (default).\n\
      -c, --columns[=COUNTERS]\n\
          Print values of counters in COUNTERS separated by spaces.\n\
          COUNTERS defaults to 'startup_ts,pkts_acctd,bytes_acctd,\n\
          pkts_not_acctd,bytes_not_acctd'.\n\
  read [OPTIONS] POOL - Read records from the pool.\n\
    Options:\n\
      -f, [-F], --[no-]follow\n\
          Whether to keep trying when blocking is required.\n\
      -s, --proto-names\n\
          Print protocol names if possible (default).\n\
      -n, --proto-numbers\n\
          Print protocol numbers.\n",
    XT_ACCT_DEFAULT_SIZE, XT_ACCT_DEFAULT_INTERVAL);
}

static void
version ()
{
  printf ("xt_acct_ctl %s\n", PACKAGE_VERSION);
}

static int
parse_uint (const char *str, unsigned int *result,
            unsigned int min_value, unsigned int max_value)
{
  unsigned int value = 0;

  if (*str < '0' || *str > '9')
    return -1;

  do
    {
      unsigned int addition = *str - '0';

      if (value > UINT_MAX / 10
          || (value == UINT_MAX / 10 && addition > UINT_MAX % 10))
        return -1;

      value = value * 10 + addition;

      if (value > max_value)
        return -1;

      ++str;
    }
  while (*str >= '0' && *str <= '9');

  if (*str || value < min_value)
    return -1;

  *result = value;

  return 0;
}

int
main (int argc, char * const argv[])
{
  const char *procfs_path = "/proc";
  const char *configfs_path = "/sys/kernel/config";
  int ipv4_p = 1;
  const char *xt_acct_name;
  const char *cmd;
  char path[PATH_MAX];
  DIR *dir;
  u_int16_t pool_id;
  int c;

  argv_0 = argv[0];

  while (1)
    {
      c = getopt_long (argc, argv, "+46", options, NULL);

      if (c == -1)
        break;

      switch (c)
        {
        case '4':
          ipv4_p = 1;
          break;
        case '6':
          ipv4_p = 0;
          break;
        case 'p':
          procfs_path = optarg;
          break;
        case 'c':
          configfs_path = optarg;
          break;
        case 'V':
          version ();
          return 0;
        case 'H':
          usage ();
          return 0;
        default:
          return 1;
        }
    }

  argc -= optind;
  argv += optind;
  optind = 1;

  if (argc == 0)
    {
      ERROR ("A command expected.");
      return 1;
    }

  xt_acct_name = ipv4_p ? IPT_ACCT_NAME : IP6T_ACCT_NAME;

#define OPEN_CONFIGFS_DIR                                                    \
  do                                                                         \
    {                                                                        \
      snprintf (path, sizeof (path), "%s/%s", configfs_path, xt_acct_name);  \
                                                                             \
      dir = opendir (path);                                                  \
                                                                             \
      if (!dir)                                                              \
        {                                                                    \
          if (errno == ENOENT)                                               \
            ERROR (                                                          \
"Directory `%s' doesn't exist. Check that module `%s' is loaded "            \
"and configfs is mounted at `%s'.",                                          \
                   path, xt_acct_name, configfs_path);                       \
          else                                                               \
            ERROR ("Failed to open directory `%s': %s.",                     \
                   path, strerror (errno));                                  \
                                                                             \
          return 2;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define CHECK_CONFIGFS_DIR                                                   \
  do                                                                         \
    {                                                                        \
      OPEN_CONFIGFS_DIR;                                                     \
      closedir (dir);                                                        \
    }                                                                        \
  while (0)

#define PARSE_POOL_ID                                                        \
  do                                                                         \
    {                                                                        \
      unsigned int pool_id_value;                                            \
                                                                             \
      argv += optind;                                                        \
      argc -= optind;                                                        \
                                                                             \
      if (argc == 0)                                                         \
        {                                                                    \
          ERROR ("A pool id expected.");                                     \
          return 1;                                                          \
        }                                                                    \
                                                                             \
      if (parse_uint (argv[0], &pool_id_value, 0, 0xFFFF) < 0)               \
        {                                                                    \
          ERROR (                                                            \
"Invalid pool id `%s', an integer between 0 and %u expected.",               \
                 argv[0], 0xFFFF);                                           \
          return 1;                                                          \
        }                                                                    \
                                                                             \
      pool_id = pool_id_value;                                               \
                                                                             \
      if (argc > 1)                                                          \
        {                                                                    \
          ERROR ("No arguments expected after pool id.");                    \
          return 1;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define READ_ATTR(NAME,VALUE,RC_NOENT,RC_READ,RC_INVAL)                      \
  do                                                                         \
    {                                                                        \
      int fd;                                                                \
      char attr_buf[32];                                                     \
      ssize_t nread;                                                         \
                                                                             \
      snprintf (path, sizeof (path), "%s/%s/%u/" NAME,                       \
                configfs_path, xt_acct_name, pool_id);                       \
                                                                             \
      fd = open (path, O_RDONLY);                                            \
                                                                             \
      if (fd < 0)                                                            \
        {                                                                    \
          if (errno == ENOENT)                                               \
            {                                                                \
              ERROR ("Pool #%u doesn't exist.", pool_id);                    \
              return (RC_NOENT);                                             \
            }                                                                \
                                                                             \
          ERROR ("Failed to read attribute `" NAME "': %s.",                 \
                 strerror (errno));                                          \
          return (RC_READ);                                                  \
        }                                                                    \
                                                                             \
      nread = read (fd, attr_buf, sizeof (attr_buf));                        \
                                                                             \
      if (nread < 0)                                                         \
        {                                                                    \
          ERROR ("Failed to read attribute `" NAME "': %s.",                 \
                 strerror (errno));                                          \
          return (RC_READ);                                                          \
        }                                                                    \
                                                                             \
      close (fd);                                                            \
                                                                             \
      if (nread < 2 || nread == sizeof (attr_buf)                            \
          || attr_buf[nread - 1] != '\n')                                    \
        {                                                                    \
          ERROR ("Attribute `" NAME "' has invalid value.");                 \
          return (RC_INVAL);                                                          \
        }                                                                    \
                                                                             \
      attr_buf[nread - 1] = 0;                                               \
                                                                             \
      if (parse_uint (attr_buf, &(VALUE), 0, UINT_MAX) < 0)                  \
        {                                                                    \
          ERROR ("Attribute `" NAME "' has invalid value.");                 \
          return (RC_INVAL);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define WRITE_ATTR(NAME,VALUE,RC_NOENT,RC_WRITE)                             \
  do                                                                         \
    {                                                                        \
      int fd;                                                                \
      char attr_buf[32];                                                     \
      size_t attr_buf_len;                                                   \
                                                                             \
      snprintf (path, sizeof (path), "%s/%s/%u/" NAME,                       \
               configfs_path, xt_acct_name, pool_id);                        \
      attr_buf_len = snprintf (attr_buf, sizeof (attr_buf), "%u", (VALUE));  \
                                                                             \
      fd = open (path, O_WRONLY);                                            \
                                                                             \
      if (fd < 0)                                                            \
        {                                                                    \
          if (errno == ENOENT)                                               \
            {                                                                \
              ERROR ("Pool #%u doesn't exist.", pool_id);                    \
              return (RC_NOENT);                                             \
            }                                                                \
                                                                             \
          ERROR ("Failed to write attribute `" NAME "': %s.",                \
                 strerror (errno));                                          \
          return (RC_WRITE);                                                 \
        }                                                                    \
                                                                             \
      if (write (fd, attr_buf, attr_buf_len) != attr_buf_len)                \
        {                                                                    \
          ERROR ("Failed to write attribute `" NAME "': %s.",                \
                 strerror (errno));                                          \
          return (RC_WRITE);                                                 \
        }                                                                    \
                                                                             \
      close (fd);                                                            \
    }                                                                        \
  while (0)
  
  cmd = argv[0];

  if (!strcmp (cmd, "list") || !strcmp (cmd, "ls"))
    {
      if (argc > 1)
        {
          ERROR ("No agruments expected for command `%s'.", cmd);
          return 1;
        }

      OPEN_CONFIGFS_DIR;

      while (1)
        {
          struct dirent *e;

          errno = 0;
          e = readdir (dir);

          if (e == NULL)
            {
              if (errno != 0)
                {
                  ERROR ("Failed to read pool list: %s.", strerror (errno));
                  return 3;
                }

              return 0;
            }

          if (e->d_name[0] >= '0' && e->d_name[0] <= '9')
            printf ("%s\n", e->d_name);
        }
    }
  else if (!strcmp (cmd, "add"))
    {
      unsigned int size = XT_ACCT_DEFAULT_SIZE;
      unsigned int interval = XT_ACCT_DEFAULT_INTERVAL;
      int ro_mode_p = 0;
      int enable_p = 0;

      ((const char **) argv)[0] = argv_0;
      
      while (1)
        {
          c = getopt_long (argc, argv, "+s:i:rweE", add_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 's':
              if (parse_uint (optarg, &size, 0, UINT_MAX) < 0)
                {
                  ERROR ("\
Invalid size `%s', an integer between 0 and %u expected.",
                         optarg, UINT_MAX);
                  return 1;
                }

              if (size == 0)
                size = XT_ACCT_DEFAULT_SIZE;
              break;
            case 'i':
              if (parse_uint (optarg, &interval, 0, 60) < 0
                  || (interval > 0 && 60 % interval != 0))
                {
                  ERROR ("\
Invalid interval `%s', zero or an integer that divides 60 expected.",
                         optarg);
                  return 1;
                }

              break;
            case 'r':
              ro_mode_p = 1;
              break;
            case 'w':
              ro_mode_p = 0;
              break;
            case 'e':
              enable_p = 1;
              break;
            case 'E':
              enable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u",
                configfs_path, xt_acct_name, pool_id);

      if (mkdir (path, 00771) < 0)
        {
          if (errno == EEXIST)
            {
              ERROR ("Pool #%u already exists.", pool_id);
              return 3;
            }
          else
            {
              ERROR ("Failed to create directory `%s': %s.",
                     path, strerror (errno));
              return 4;
            }
        }

      WRITE_ATTR ("size", size, 5, 5);
      WRITE_ATTR ("interval", interval, 5, 5);
      WRITE_ATTR ("ro_mode", ro_mode_p, 5, 5);
      if (enable_p)
        WRITE_ATTR ("enabled", 1, 5, 5);
    }
  else if (!strcmp (cmd, "rm") || !strcmp(cmd, "del"))
    {
      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u",
                configfs_path, xt_acct_name, pool_id);

      if (rmdir (path) < 0)
        {
          if (errno == ENOENT)
            {
              ERROR ("Pool #%u doesn't exist.", pool_id);
              return 3;
            }

          ERROR ("Failed to remove directory `%s': %s.",
                 path, strerror (errno));
          return 4;
        }
    }
  else if (!strcmp (cmd, "enable"))
    {
      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;
      WRITE_ATTR ("enabled", 1, 3, 4);
    }
  else if (!strcmp (cmd, "disable"))
    {
      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;
      WRITE_ATTR ("enabled", 0, 3, 4);
    }
  else if (!strcmp (cmd, "exists"))
    {
      struct stat stat_buf;

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u",
                configfs_path, xt_acct_name, pool_id);

      if (stat (path, &stat_buf) < 0)
        {
          if (errno == ENOENT)
            return 3;

          ERROR ("Failed to open directory `%s': %s.",
                 path, strerror (errno));
          return 4;
        }

      if (!S_ISDIR (stat_buf.st_mode))
        {
          ERROR ("Failed to open directory `%s': %s",
                 path, strerror (ENOTDIR));
          return 4;
        }
    }
  else if (!strcmp (cmd, "enabled"))
    {
      unsigned int value;

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;
      READ_ATTR ("enabled", value, 3, 4, 4);

      if (value != 1)
        return 5;
    }
  else if (!strcmp (cmd, "info"))
    {
      enum column
      {
        COLUMN_NONE = 0,
        COLUMN_ENABLED = 1,
        COLUMN_RO_MODE = 2,
        COLUMN_SIZE = 4,
        COLUMN_INTERVAL = 8,
        COLUMN_ALL = COLUMN_ENABLED | COLUMN_RO_MODE | COLUMN_SIZE
                     | COLUMN_INTERVAL
      };

      int human_readable_p = 1;
      enum column columns = COLUMN_ALL;
      enum column column_list[] = {
          COLUMN_ENABLED, COLUMN_RO_MODE, COLUMN_SIZE, COLUMN_INTERVAL
        };

      unsigned int enabled_p, ro_mode_p, size, interval;

      ((const char **) argv)[0] = argv_0;

      while (1)
        {
          c = getopt_long (argc, argv, "+hc::", info_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'h':
              human_readable_p = 1;
              columns = COLUMN_ALL;
              column_list[0] = COLUMN_ENABLED;
              column_list[1] = COLUMN_RO_MODE;
              column_list[2] = COLUMN_SIZE;
              column_list[3] = COLUMN_INTERVAL;
              break;
            case 'c':
              if (optarg == NULL)
                {
                  columns = COLUMN_ALL;
                  column_list[0] = COLUMN_ENABLED;
                  column_list[1] = COLUMN_RO_MODE;
                  column_list[2] = COLUMN_SIZE;
                  column_list[3] = COLUMN_INTERVAL;
                }
              else
                {
                  unsigned int i;
                  const char *s = optarg;

                  if (!*s)
                    {
                      ERROR ("Empty attribute list.");
                      return 1;
                    }

                  columns = COLUMN_NONE;
                  column_list[0] = COLUMN_NONE;
                  column_list[1] = COLUMN_NONE;
                  column_list[2] = COLUMN_NONE;
                  column_list[3] = COLUMN_NONE;

                  for (i = 0; i < ARRAY_SIZE (column_list); ++ i)
                    {
#define CHECK_TOKEN(TOKEN,COLUMN)                                            \
                      if (!strncmp (s, (TOKEN), strlen (TOKEN)) == 0)        \
                        {                                                    \
                          s += strlen (TOKEN);                               \
                                                                             \
                          if (*s && *s != ',')                               \
                            break;                                           \
                                                                             \
                          if (columns & (COLUMN))                            \
                            {                                                \
                              ERROR ("Token `" TOKEN "' is duplicated.");    \
                              return 1;                                      \
                            }                                                \
                                                                             \
                          columns |= COLUMN;                                 \
                          column_list[i] = COLUMN;                           \
                                                                             \
                          if (!*s)                                           \
                            break;                                           \
                                                                             \
                          continue;                                          \
                        }

                      CHECK_TOKEN ("enabled", COLUMN_ENABLED);
                      CHECK_TOKEN ("ro_mode", COLUMN_RO_MODE);
                      CHECK_TOKEN ("size", COLUMN_SIZE);
                      CHECK_TOKEN ("interval", COLUMN_INTERVAL);
#undef CHECK_TOKEN

                      break;
                    }

                  if (*s)
                    {
                      ERROR ("Invalid attribute list `%s'.", optarg);
                      return 1;
                    }
                }

              human_readable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      if (columns & COLUMN_ENABLED)
        READ_ATTR ("enabled", enabled_p, 3, 4, 5);
      if (columns & COLUMN_RO_MODE)
        READ_ATTR ("ro_mode", ro_mode_p, 3, 4, 5);
      if (columns & COLUMN_SIZE)
        READ_ATTR ("size", size, 3, 4, 5);
      if (columns & COLUMN_INTERVAL)
        READ_ATTR ("interval", interval, 3, 4, 5);

      if (human_readable_p)
        printf ("\
Pool is enabled: %s\n\
Pool is in read-only mode: %s\n\
Pool size: %u\n\
Pool aggregation interval: %u\n",
                enabled_p ? "yes" : "no", ro_mode_p ? "yes" : "no",
                size, interval);
      else
        {
          unsigned int i;

          for (i = 0; i < ARRAY_SIZE (column_list); ++i)
            {
              enum column c = column_list[i];

              if (c == COLUMN_NONE)
                continue;

              if (i > 0)
                printf (" ");

              switch (c)
                {
                  case COLUMN_ENABLED:
                    printf (enabled_p ? "yes" : "no");
                    break;
                  case COLUMN_RO_MODE:
                    printf (ro_mode_p ? "yes" : "no");
                    break;
                  case COLUMN_SIZE:
                    printf ("%u", size);
                    break;
                  case COLUMN_INTERVAL:
                    printf ("%u", interval);
                    break;
                  default:
                    break;
                }
            }
        }
    }
  else if (!strcmp (cmd, "cfg"))
    {
      unsigned int size_set_p = 0, size = 0;
      unsigned int interval_set_p = 0, interval = 0;
      int ro_mode_set_p = 0, ro_mode_p = 0;
      int enable_p = 0;

      ((const char **) argv)[0] = argv_0;
      
      while (1)
        {
          c = getopt_long (argc, argv, "+s:i:rweE", cfg_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 's':
              if (parse_uint (optarg, &size, 0, UINT_MAX) < 0)
                {
                  ERROR ("\
Invalid size `%s', an integer between 0 and %u expected.",
                         optarg, UINT_MAX);
                  return 1;
                }

              if (size == 0)
                size = XT_ACCT_DEFAULT_SIZE;
              size_set_p = 1;
              break;
            case 'i':
              if (parse_uint (optarg, &interval, 0, 60) < 0
                  || (interval > 0 && 60 % interval != 0))
                {
                  ERROR ("\
Invalid interval `%s', zero or an integer that divides 60 expected.",
                         optarg);
                  return 1;
                }

              interval_set_p = 1;
              break;
            case 'r':
              ro_mode_p = 1;
              ro_mode_set_p = 1;
              break;
            case 'w':
              ro_mode_p = 0;
              ro_mode_set_p = 1;
              break;
            case 'e':
              enable_p = 1;
              break;
            case 'E':
              enable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      if (size_set_p)
        WRITE_ATTR ("size", size, 3, 4);
      if (interval_set_p)
        WRITE_ATTR ("interval", interval, 3, 4);
      if (ro_mode_set_p)
        WRITE_ATTR ("ro_mode", ro_mode_p, 3, 4);
      if (enable_p)
        WRITE_ATTR ("enabled", 1, 3, 4);
    }
  else if (!strcmp (cmd, "stat"))
    {
      enum column
      {
        COLUMN_NONE = 0,
        COLUMN_ENABLED_TS = 1,
        COLUMN_PKTS_ACCT = 2,
        COLUMN_BYTES_ACCT = 4,
        COLUMN_PKTS_NOT_ACCT = 8,
        COLUMN_BYTES_NOT_ACCT = 16,
        COLUMN_ALL = COLUMN_ENABLED_TS | COLUMN_PKTS_ACCT | COLUMN_BYTES_ACCT
                     | COLUMN_PKTS_NOT_ACCT | COLUMN_BYTES_NOT_ACCT
      };

      int human_readable_p = 1;
      enum column columns = COLUMN_ALL;
      enum column column_list[] = {
          COLUMN_ENABLED_TS, COLUMN_PKTS_ACCT, COLUMN_BYTES_ACCT,
          COLUMN_PKTS_NOT_ACCT, COLUMN_BYTES_NOT_ACCT
        };

      struct xt_acct_stat stat_buf;
      int fd;
      ssize_t nread;

      ((const char **) argv)[0] = argv_0;

      while (1)
        {
          c = getopt_long (argc, argv, "+hc::", stat_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'h':
              human_readable_p = 1;
              columns = COLUMN_ALL;
              column_list[0] = COLUMN_ENABLED_TS;
              column_list[1] = COLUMN_PKTS_ACCT;
              column_list[2] = COLUMN_BYTES_ACCT;
              column_list[3] = COLUMN_PKTS_NOT_ACCT;
              column_list[4] = COLUMN_BYTES_NOT_ACCT;
              break;
            case 'c':
              if (optarg == NULL)
                {
                  columns = COLUMN_ALL;
                  column_list[0] = COLUMN_ENABLED_TS;
                  column_list[1] = COLUMN_PKTS_ACCT;
                  column_list[2] = COLUMN_BYTES_ACCT;
                  column_list[3] = COLUMN_PKTS_NOT_ACCT;
                  column_list[4] = COLUMN_BYTES_NOT_ACCT;
                }
              else
                {
                  unsigned int i;
                  const char *s = optarg;

                  if (!*s)
                    {
                      ERROR ("Empty counter list.");
                      return 1;
                    }

                  columns = COLUMN_NONE;
                  column_list[0] = COLUMN_NONE;
                  column_list[1] = COLUMN_NONE;
                  column_list[2] = COLUMN_NONE;
                  column_list[3] = COLUMN_NONE;
                  column_list[4] = COLUMN_NONE;

                  for (i = 0; i < ARRAY_SIZE (column_list); ++ i)
                    {
#define CHECK_TOKEN(TOKEN,COLUMN)                                            \
                      if (!strncmp (s, (TOKEN), strlen (TOKEN)) == 0)        \
                        {                                                    \
                          s += strlen (TOKEN);                               \
                                                                             \
                          if (*s && *s != ',')                               \
                            break;                                           \
                                                                             \
                          if (columns & (COLUMN))                            \
                            {                                                \
                              ERROR ("Token `" TOKEN "' is duplicated.");    \
                              return 1;                                      \
                            }                                                \
                                                                             \
                          columns |= COLUMN;                                 \
                          column_list[i] = COLUMN;                           \
                                                                             \
                          if (!*s)                                           \
                            break;                                           \
                                                                             \
                          continue;                                          \
                        }

                      CHECK_TOKEN ("enabled_ts", COLUMN_ENABLED_TS);
                      CHECK_TOKEN ("pkts_acct", COLUMN_PKTS_ACCT);
                      CHECK_TOKEN ("bytes_acct", COLUMN_BYTES_ACCT);
                      CHECK_TOKEN ("pkts_not_acct", COLUMN_PKTS_NOT_ACCT);
                      CHECK_TOKEN ("bytes_not_acct", COLUMN_BYTES_NOT_ACCT);
#undef CHECK_TOKEN

                      break;
                    }

                  if (*s)
                    {
                      ERROR ("Invalid counter list `%s'.", optarg);
                      return 1;
                    }
                }

              human_readable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u/stat",
                configfs_path, xt_acct_name, pool_id);

      fd = open (path, O_RDONLY);

      if (fd < 0)
        {
          if (errno == ENOENT)
            {
              ERROR ("Pool #%u doesn't exist.", pool_id);
              return 3;
            }

          ERROR ("Failed to read counters: %s.", strerror (errno));
          return 5;
        }

      nread = read (fd, &stat_buf, sizeof (stat_buf));

      if (nread < 0)
        {
          if (errno == ENODATA)
            {
              ERROR ("Pool #%u is disabled.", pool_id);
              return 4;
            }

          ERROR ("Failed to read counters: %s.", strerror (errno));
          return 5;
        }

      if (nread != sizeof (stat_buf))
        {
          ERROR ("Invalid counters format.");
          return 5;
        }

      close (fd);

      if (human_readable_p)
        printf ("\
Enabled at timestamp: %" PRIu64 "\n\
Packets accounted: %" PRIu64 "\n\
Bytes accounted: %" PRIu64 "\n\
Packets not accounted: %" PRIu64 "\n\
Bytes not accounted: %" PRIu64 "\n",
                stat_buf.enabled_ts, stat_buf.pkts_acct, stat_buf.bytes_acct,
                stat_buf.pkts_not_acct, stat_buf.bytes_not_acct);
      else
        {
          unsigned int i;

          for (i = 0; i < ARRAY_SIZE (column_list); ++i)
            {
              enum column c = column_list[i];

              if (c == COLUMN_NONE)
                continue;

              if (i > 0)
                printf (" ");

              switch (c)
                {
                  case COLUMN_ENABLED_TS:
                    printf ("%" PRIu64, stat_buf.enabled_ts);
                    break;
                  case COLUMN_PKTS_ACCT:
                    printf ("%" PRIu64, stat_buf.pkts_acct);
                    break;
                  case COLUMN_BYTES_ACCT:
                    printf ("%" PRIu64, stat_buf.bytes_acct);
                    break;
                  case COLUMN_PKTS_NOT_ACCT:
                    printf ("%" PRIu64, stat_buf.pkts_not_acct);
                    break;
                  case COLUMN_BYTES_NOT_ACCT:
                    printf ("%" PRIu64, stat_buf.bytes_not_acct);
                    break;
                  default:
                    break;
                }
            }
        }
    }
  else if (!strcmp (cmd, "read"))
    {
      int follow_p = 0;
      int numeric_p = 0;
      struct pollfd pollfd = { .events = POLLIN };
      void *buf;
      size_t record_size = ipv4_p ? sizeof (struct ipt_acct_record)
                                  : sizeof (struct ip6t_acct_record);
      size_t buf_size = 4096 - 4096 % record_size;

      ((const char **) argv)[0] = argv_0;

      while (1)
        {
          c = getopt_long (argc, argv, "+fFsn", read_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'f':
              follow_p = 1;
              break;
            case 'F':
              follow_p = 0;
              break;
            case 's':
              numeric_p = 0;
              break;
            case 'n':
              numeric_p = 1;
              break;
            default:
              return 1;
            }
        }

      PARSE_POOL_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/net/%s", procfs_path, xt_acct_name);

      pollfd.fd = open (path, O_RDONLY | O_NONBLOCK);

      if (pollfd.fd < 0)
        {
          if (errno == ENOENT)
            {
              ERROR ("\
File `%s' doesn't exist. Make sure module `%s' is loaded and procfs is \
mounted at `%s'.", path, xt_acct_name, procfs_path);
              return 2;
            }

          ERROR ("Failed to open file `%s': %s.",
                 path, strerror (errno));
          return 3;
        }

      if (ioctl (pollfd.fd, XT_ACCT_IOCTL_SETUP,
                 (unsigned long) pool_id) < 0)
        {
          ERROR ("Failed to setup the file descriptor: %s.",
                 strerror (errno));
          return 4;
        }

      buf = malloc (buf_size);

      if (!buf)
        {
          ERROR ("Failed to allocate buffer for records: %s.",
                 strerror (errno));
          return 5;
        }

      while (1)
        {
          ssize_t n;
          int result = poll (&pollfd, 1, follow_p ? -1 : 0);

          if (result < 0)
            {
              ERROR ("Failed to read records: %s.", strerror (errno));
              return 4;
            }

          if (result == 0)
            {
              if (follow_p)
                continue;
              else
                return 0;
            }

          n = read (pollfd.fd, buf, buf_size);

          if (n < 0)
            {
              ERROR ("Failed to read records: %s.", strerror (errno));
              return 4;
            }

          if (ipv4_p)
            {
              struct ipt_acct_record *record;
              char src[] = "XXX.XXX.XXX.XXX";
              char dst[] = "XXX.XXX.XXX.XXX";
              struct protoent *p;

              for (record = buf; n >= record_size;
                   record += 1, n -= record_size)
                {
                  inet_ntop (AF_INET, &record->src, src, sizeof (src));
                  inet_ntop (AF_INET, &record->dst, dst, sizeof (src));

                  if (numeric_p)
                    p = NULL;
                  else
                    p = getprotobynumber (record->proto);

                  if (p)
                    printf ("%" PRIu32 " %s %" PRIu16 " %s %" PRIu16
                            " %s %" PRIu32 " %" PRIu32
                            " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                            record->tag,
                            src, record->sport, dst, record->dport,
                            p->p_name, record->conn_mark,
                            record->npkts, record->nbytes,
                            record->first_ts, record->last_ts);
                  else
                    printf ("%" PRIu32 " %s %" PRIu16 " %s %" PRIu16
                            " %" PRIu8 " %" PRIu32 " %" PRIu32
                            " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                            record->tag,
                            src, record->sport, dst, record->dport,
                            record->proto, record->conn_mark,
                            record->npkts, record->nbytes,
                            record->first_ts, record->last_ts);
                }
            }
          else
            {
              struct ip6t_acct_record *record;
              char src[] = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXX.XXX.XXX.XXX";
              char dst[] = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXX.XXX.XXX.XXX";
              struct protoent *p;

              for (record = buf; n >= record_size;
                   record += 1, n -= record_size)
                {
                  inet_ntop (AF_INET6, &record->src, src, sizeof (src));
                  inet_ntop (AF_INET6, &record->dst, dst, sizeof (src));

                  if (numeric_p)
                    p = NULL;
                  else
                    p = getprotobynumber (record->proto);

                  if (p)
                    printf ("%" PRIu32 " %s %" PRIu16 " %s %" PRIu16
                            " %s %" PRIu32 " %" PRIu32
                            " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                            record->tag,
                            src, record->sport, dst, record->dport,
                            p->p_name, record->conn_mark,
                            record->npkts, record->nbytes,
                            record->first_ts, record->last_ts);
                  else
                    printf ("%" PRIu32 " %s %" PRIu16 " %s %" PRIu16
                            " %" PRIu8 " %" PRIu32 " %" PRIu32
                            " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                            record->tag,
                            src, record->sport, dst, record->dport,
                            record->proto, record->conn_mark,
                            record->npkts, record->nbytes,
                            record->first_ts, record->last_ts);
                }
 
            }
        }
    }
  else
    {
      ERROR ("Unknown command `%s'.", cmd);
      return 1;
    }

  return 0;
}

