Quick doc
=========

Based on https://access.redhat.com/documentation/de-de/red_hat_enterprise_linux/8/html/using_selinux/writing-a-custom-selinux-policy_using-selinux

Created by:

.. code-block:: sh

	sepolicy generate --init /usr/libexec/gromox

Edit gromox.te and add the output of:

.. code-block:: sh

	ausearch -m AVC -ts recent | audit2allow

Possible improvements:

* gromox TCP ports should be assigned to socket types
