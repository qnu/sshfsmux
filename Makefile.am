## Process this file with automake to produce Makefile.in

bin_PROGRAMS = sshfsm

sshfsm_SOURCES = sshfsm.c cache.c cache.h table.c table.h
if FUSE_OPT_COMPAT
sshfsm_SOURCES += compat/fuse_opt.c compat/fuse_opt.h
endif

sshfsm_LDADD = $(SSHFSM_LIBS)
sshfsm_CFLAGS = $(SSHFSM_CFLAGS)
sshfsm_CPPFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -DLIBDIR=\"$(libdir)\"

EXTRA_DIST = sshnodelay.c FAQ.txt
CLEANFILES = sshnodelay.so

dist_man_MANS = sshfsm.1

if SSH_NODELAY_SO
all-local: sshnodelay.so

install-exec-local: sshnodelay.so
	test -z "$(libdir)" || $(mkdir_p) "$(DESTDIR)$(libdir)"
	$(INSTALL) -m 755 sshnodelay.so "$(DESTDIR)$(libdir)/sshnodelay.so"

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/sshnodelay.so"

sshnodelay.so:
	$(CC) -Wall -W -s --shared -fPIC $(sshnodelay_libs) sshnodelay.c -o sshnodelay.so
endif
