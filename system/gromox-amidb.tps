[Unit]
Description=Gromox amidb service
Documentation=man:amidb(8gx) man:amidb.cfg(5gx)
PartOf=gromox-agent.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/amidb

[Install]
WantedBy=multi-user.target
