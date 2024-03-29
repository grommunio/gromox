[Unit]
Description=Gromox mail spooler
Documentation=man:delivery(8gx)
Requires=gromox-delivery-queue.service
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/delivery
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target
