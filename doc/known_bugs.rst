
Known Bugs for Developers
=========================

* xfce4-terminal (more generally, everything libvte-based?): when using
  xfce4-terminal's paste functionality, certain characters can get eaten if and
  when $TERM is running screen, thereby producing e.g. bad SMTP input paste
  that have broken base64, which then cannot be decoded properly.
