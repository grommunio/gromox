
Known incompatibilities involving third-party software.


Noteworthy issues for administrators and packagers
==================================================

* Due to https://gitlab.gnome.org/GNOME/libxml2/-/issues/508 ,
  libxml2 versions 2.9.11 <= v < 2.11.0 cause HTML e-mail message bodies to
  change <o:p> to <p>, which causes the insertion of extraneous empty lines
  upon reception of e-mail.


Noteworthy issues for developers
================================

* xfce4-terminal (more generally, everything libvte-based?): when using
  xfce4-terminal's paste functionality, certain characters can get eaten if and
  when $TERM is running screen, thereby producing e.g. bad SMTP input paste
  that have broken base64, which then cannot be decoded properly.
