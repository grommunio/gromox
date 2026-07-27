
Just try to follow the existing code. A few points of note:

* The TAB control character is used to represent indentation (nesting level) of
  a block of control. They are superior to spaces because they allow users to
  set the rendering width as narrow or wide as they wish.

* Use spaces to justify, i.e.: When long statements are folded to become
  multiple lines AND the dev decides to align around a particular feature (such
  as the '=' operator), spaces should be used. (Unparticular linefolding often
  happens with \t.) It is understood that C++ nested functions can lead to
  interesting patterns of tabs and spaces; it is what it is.

* Preferred max line length is 80 columns. Comments should aim for it more so
  than C++ statements (these are known to be verbose). In commit messages,
  70/72 is preferred, so as to leave room for `> ` indentations when text is
  quoted in an e-mail reply.

* `LKCS <https://www.kernel.org/doc/html/v7.1/process/coding-style.html>`_ has
  a lot of good points still.
