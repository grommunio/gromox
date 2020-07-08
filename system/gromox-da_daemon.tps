[Unit]
Description=Gromox da_daemon service
Documentation=man:da_daemon(8gx) man:da.cfg(5gx)
PartOf=gromox-da.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/da_daemon

[Install]
WantedBy=multi-user.target
