#!/bin/sh

cd LIBRARY && make && cd ..
cd MTA_SYSTEM
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/epoll_scheduler .
ln -s ../LIBRARY/mapi_lib .
make && make release && cd ..
cd MRA_SYSTEM
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/epoll_scheduler
make && make release && cd ..
cd EXCHANGE_SYSTEM
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/epoll_scheduler .
ln -s ../LIBRARY/mapi_lib .
ln -s ../LIBRARY/rpc_lib .
ln -s ../LIBRARY/webkit_lib .
make && make release && cd ..
cd AGENT_SERVICE
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/mapi_lib .
ln -s ../LIBRARY/rpc_lib .
ln -s ../LIBRARY/webkit_lib .
make && make release && cd ..
cd DOMAIN_ADMIN
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/mapi_lib .
ln -s ../LIBRARY/rpc_lib .
ln -s ../LIBRARY/webkit_lib .
make && make release && cd ..
cd SYSTEM_ADMIN
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
ln -s ../LIBRARY/mapi_lib .
ln -s ../LIBRARY/webkit_lib .
make && make release && cd ..
cd ARCHIVE_SYSTEM
ln -s ../LIBRARY/common .
ln -s ../LIBRARY/email_lib .
make && make release && cd ..
