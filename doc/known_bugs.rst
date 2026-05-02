
Known incompatibilities involving third-party software.


Noteworthy issues for administrators and packagers
==================================================

* Due to https://gitlab.gnome.org/GNOME/libxml2/-/issues/508 ,
  libxml2 versions 2.9.11 <= v < 2.11.0 cause HTML e-mail message bodies to
  change <o:p> to <p>, which causes the insertion of extraneous empty lines
  upon reception of e-mail.

* Due to "optimizations" in various `malloc` implementations – and thus nothing
  that Gromox can control directly – certain allocations are not always
  returned back to the operating system. This makes gromox-imap appear to have
  high memory consumption (and possibly dying when not enough system memory is
  installed) after obtaining the listview for a folder with 70000 messages.
  https://github.com/grommunio/gromox/issues/214

* Some C++ shared libraries can not be unloaded
  (when `readelf -aW` outputs "UNIQUE"-type symbols). Components like
  libgromox_common.so.0, once loaded into a process, stay resident across
  dlclose-dlopen calls. This generally affects programs that use pam_gromox.so.
  These programs (e.g. keycloak) need to be restarted after a Gromox update.


Noteworthy issues for developers
================================

* xfce4-terminal (more generally, everything libvte-based?): when using
  xfce4-terminal's paste functionality, certain characters can get eaten if and
  when $TERM is running screen, thereby producing e.g. bad SMTP input paste
  that have broken base64, which then cannot be decoded properly.
