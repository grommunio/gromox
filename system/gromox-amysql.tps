[Unit]
Description=Gromox amysql service
Documentation=man:amysql(8gx) man:amysql.cfg(5gx)
PartOf=gromox-agent.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/amysql

[Install]
WantedBy=multi-user.target
