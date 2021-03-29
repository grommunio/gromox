[Unit]
Description=Gromox mail spooler
Documentation=man:delivery(8gx)
PartOf=gromox-mta.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/delivery
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
