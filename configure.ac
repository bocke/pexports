# configure.ac for pexports
# Created 2013-05-29 by Keith Marshall <keithmarshall@users.sourceforge.net>
# Copyright (C) 2013, 2015, MinGW.org Project.
#
  AC_INIT([pexports],[0.47],[http://mingw.org/reporting_bugs])
#
# Directory organisation.
#
  AC_CONFIG_SRCDIR([pexports.c])
  AC_CONFIG_AUX_DIR([build-aux])
#
# We use the host_os component of the canonical triplet as an identifier
# in generated package names.
#
  AC_CANONICAL_HOST
#
# Identify the compiler, lexical analyser, and parser generator.
#
  AC_PROG_CC
  AC_PROG_LEX
  AC_PROG_YACC
#
# Initialise flags for the lexical analyser, and the parser generator.
# FIXME: these YFLAGS gratuitously assume that the parser generator will
# be GNU bison; we may need to adjust for yacc or byacc.
#
  AC_SUBST([LFLAGS])
  AC_SUBST([YFLAGS],[${YFLAGS-'--defines=$*.h'}])
#
# Other tools used for installation, and distribution packaging.
#
  AC_PROG_LN_S
  AC_PROG_MKDIR_P
  AC_PROG_INSTALL
#
# Generate configuration.
#
  AC_CONFIG_FILES([Makefile])
  AC_OUTPUT
#
# configure.ac: end of file
