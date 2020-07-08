[Unit]
Description=Gromox sa_daemon service
Documentation=man:sa_daemon(8gx) man:sa.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/sa_daemon

[Install]
WantedBy=multi-user.target
