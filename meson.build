project(
  'pexports',
  'c',
  version: '0.47',
  license: 'GPL',
  meson_version: '>=0.63.0',
  default_options: [
    'c_std=c99',
    'warning_level=2',
  ]
)

# Set POSIX feature test macro for compatible systems
if host_machine.system() in ['linux', 'freebsd', 'openbsd', 'netbsd', 'sunos', 'darwin']
  add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')
endif

# Declare a dependency for flex and bison
flex = find_program('flex', 'lex')
bison = find_program('bison', 'yacc')

# Generate lexer from hlex.l
hlex_c = custom_target(
  'hlex.c',
  input: 'hlex.l',
  output: 'hlex.c',
  command: [flex, '-o', '@OUTPUT@', '@INPUT@']
)

# Generate parser from hparse.y (produces both .c and .h)
hparse_c = custom_target(
  'hparse.c',
  input: 'hparse.y',
  output: ['hparse.c', 'hparse.h'],
  command: [bison, '--defines=@OUTDIR@/hparse.h', '-o', '@OUTPUT0@', '@INPUT@']
)

# Main executable
pexports = executable(
  'pexports',
  ['pexports.c', 'str_tree.c', hlex_c, hparse_c],
  include_directories: include_directories('.'),
  c_args: [
    '-DPACKAGE_VERSION_STRING="@0@"'.format(meson.project_version()),
    '-DPACKAGE_BUG_REPORT="http://mingw.org/reporting_bugs"'
  ]
)
