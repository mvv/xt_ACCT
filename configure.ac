AC_PREREQ([2.59])

AC_INIT([xt_ACCT], [1.00])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

if test "x${host_os}" != "xlinux-gnu"; then
  AC_MSG_ERROR([Host OS is not GNU/Linux])
fi

AC_PROG_MAKE_SET
AC_PROG_CC
AC_CHECK_TOOL([LD], [ld])
if test -z "${LD}"; then
  AC_MSG_ERROR([Couldn't find linker])
fi
m4_ifdef([AC_PROG_SED], [AC_PROG_SED], [AC_SUBST([SED], [sed])])
AC_PROG_INSTALL
m4_ifdef([AC_PROG_MKDIR_P], [AC_PROG_MKDIR_P],
         [AC_SUBST([MKDIR_P], ["\@S|@(INSTALL) -d"])])
PKG_PROG_PKG_CONFIG

kernel_ver=
AC_ARG_WITH([kernel],
  [AS_HELP_STRING([--with-kernel=PATH], 
                  [use the kernel development files in PATH])],
  [if ! test -d "${with_kernel}"; then
     AC_MSG_ERROR([\
The path `${with_kernel}' @{:@specified via --with-kernel@:}@ is not \
a directory.])
   fi
   if test -f "${with_kernel}/Makefile" -a \
           -f "${with_kernel}/include/config/kernel.release"; then
      kernel_ver=`cat "${with_kernel}/include/config/kernel.release"`
   else
     AC_MSG_ERROR([\
The directory `${with_kernel}' doesn't look like the root of a kernel \
build tree.])
   fi],
  [if test "x${build_alias}" != "x${host_alias}"; then
     AC_MSG_ERROR([\
Cross-compiling, kernel build tree path autodetection disabled. \
Please use --with-kernel.])
   fi
   kernel_ver=`uname -r`
   if test -z "${kernel_ver}"; then
     AC_MSG_ERROR([\
Couldn't get the kernel version through uname, use --with-kernel.])
   fi
   with_kernel=
   if test -d "/lib/modules/${kernel_ver}"; then
     build_dir="/lib/modules/${kernel_ver}/build"
     if test -f "${build_dir}/Makefile" -a \
             -f "${build_dir}/include/config/kernel.release"; then
         with_kernel="${build_dir}"
     fi
   fi
   if test -z "${with_kernel}"; then
     AC_MSG_ERROR([\
Couldn't autodetect kernel build tree path, use --with-kernel.])
   fi
   kernel_ver=`cat "${with_kernel}/include/config/kernel.release"`
   if ! test "$?" = "0"; then
     AC_MSG_ERROR([\
Couldn't autodetect kernel build tree path, use --with-kernel.])
   fi])

case "${kernel_ver}" in
  2.6.*)
    ;;
  *)
    AC_MSG_ERROR([Unsupported kernel version `${kernel_ver}'.])
    ;;
esac

AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([
#include "${with_kernel}/include/linux/version.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
# error "Only 2.6.18+ kernels are supported."
#endif], [])],
  [], [AC_MSG_ERROR([Only 2.6.18+ kernels are supported.])])

AC_MSG_CHECKING([for procfs support])
AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([
#include "${with_kernel}/include/linux/version.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
# include "${with_kernel}/include/linux/autoconf.h"
#else
# include "${with_kernel}/include/generated/autoconf.h"
#endif
#if !defined(CONFIG_PROC_FS)
# error "Procfs is disabled."
#endif], [])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([Procfs support is required.])])

AC_MSG_CHECKING([for configfs support])
AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([
#include "${with_kernel}/include/linux/version.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
# include "${with_kernel}/include/linux/autoconf.h"
#else
# include "${with_kernel}/include/generated/autoconf.h"
#endif
#if !defined(CONFIG_CONFIGFS_FS) && !defined(CONFIG_CONFIGFS_FS_MODULE)
# error "Configfs is disabled."
#endif], [])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([Configfs support is required.])])

AC_SUBST([KERNEL_DIR], [${with_kernel}])
AC_SUBST([KERNEL_VERSION], [${kernel_ver}])

AC_ARG_VAR([IPTABLES], [path to iptables binary])
AC_ARG_VAR([IPTABLES_CFLAGS], [C compiler flags for iptables])
AC_ARG_VAR([IPTABLES_VERSION], [iptables version])
AC_ARG_VAR([IPTABLES_LIBDIR], [path to iptables libraries directory])

pc_found=
if test "x$ac_cv_env_IPTABLES_CFLAGS_set" != "xset"; then
  if test -n "${PKG_CONFIG}"; then
    PKG_CHECK_EXISTS([xtables],
      [AC_DEFINE([IPTABLES14PLUS])
       pc_found=yes
       IPTABLES_CFLAGS=`${PKG_CONFIG} --cflags xtables`
       if ! test "$?" = "0"; then
         AC_MSG_ERROR([pkg-config execution failed.])
       fi
       if test -z "${IPTABLES_LIBDIR}"; then
         IPTABLES_LIBDIR=`${PKG_CONFIG} --variable=xtlibdir xtables`
         if ! test "$?" = "0"; then
           AC_MSG_ERROR([pkg-config execution failed.])
         fi
       fi])
  fi
fi

if test -z "$pc_found"; then
  old_CFLAGS="${CFLAGS}"
  CFLAGS="${CFLAGS} ${IPTABLES_CFLAGS}"
  dnl We only have the iptables CFLAGS, so we need to force the compiler
  dnl usage for headers checking by using the fourth argument of
  dnl AC_CHECK_HEADER[S]
  AC_CHECK_HEADER([xtables.h],
    [AC_DEFINE([IPTABLES14PLUS])],
    [AC_CHECK_HEADERS([iptables.h ip6tables.h], [],
       [AC_MSG_ERROR([Need iptables.h and ip6tables.h])],
       [AC_INCLUDES_DEFAULT])
     dnl OK, looks like we are stuck with iptables 1.3.x
     dnl Let's try to determine the exact version.
     if test -z "${IPTABLES_VERSION}"; then
       if test "x${build_alias}" != "x${host_alias}"; then
         AC_MSG_ERROR([\
Cross-compiling, iptables version autodetection disabled. \
Please use the IPTABLES_VERSION variable.])
       else
         AC_CHECK_PROG([IPTABLES], [iptables], [iptables])
         if test -z "${IPTABLES}"; then
           AC_MSG_ERROR([\
Couldn't find iptables binary. Use the IPTABLES variable])
         fi
         AC_MSG_CHECKING([iptables version])
         IPTABLES_VERSION=`${IPTABLES} -V | sed -e 's/^iptables v//'`
         if test "$?" != "0"; then
           AC_MSG_RESULT([no])
           AC_MSG_ERROR([Execution of `${IPTABLES} -V` failed.])
         fi
         AC_MSG_RESULT([${IPTABLES_VERSION}])
       fi
     fi
     case "${IPTABLES_VERSION}" in
       1.3.*)
         AC_DEFINE_UNQUOTED([IPTABLES_VERSION], ["${IPTABLES_VERSION}"])
         ;;
       1.4.*)
         ;;
       *)
         AC_MSG_ERROR([Unsupported iptables version `${IPTABLES_VERSION}'.])
         ;;
     esac], [AC_INCLUDES_DEFAULT])
  CFLAGS="${old_CFLAGS}"
fi

if test -z "${IPTABLES_LIBDIR}"; then
  dnl Try some defaults
  for d in /lib/iptables /lib/xtables /usr/lib/iptables \
           /usr/lib/xtables "${exec_prefix}/lib/iptables" \
           "${exec_prefix}/lib/xtables"; do
    if test -z "${IPTABLES_LIBDIR}" -a -d "$d" -a \
            -f "${d}/libipt_SNAT.so"; then
      IPTABLES_LIBDIR="$d"
    fi
  done
  if test -z "${IPTABLES_LIBDIR}"; then
    AC_MSG_ERROR([\
Couldn't autodetect iptables libraries directory, use the IPTABLES_LIBDIR \
variable.])
  fi
elif test "x$ac_cv_end_IPTABLES_LIBDIR" = "xset"; then
  if ! test -d "${IPTABLES_LIBDIR}"; then
    AC_MSG_ERROR([\
The path '${IPTABLES_LIBDIR}' @{:@specified via IPTABLES_LIBDIR@:}@ is not \
a directory.])
  fi
  if ! test -f "${IPTABLES_LIBDIR}/libipt_SNAT.so"; then
    AC_MSG_ERROR([\
The directory '${IPTABLES_LIBDIR}' doesn't look like an iptables libraries
directory.])
  fi
fi

AC_SUBST([IPTABLES_CFLAGS], [${IPTABLES_CFLAGS}])
AC_SUBST([IPTABLES_LIBDIR], [${IPTABLES_LIBDIR}])

AC_CONFIG_FILES([Makefile Kbuild])
AC_OUTPUT

