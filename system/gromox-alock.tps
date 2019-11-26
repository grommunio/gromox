[Unit]
Description=Gromox alock service
Documentation=man:alock(8gx) man:alock.cfg(5gx)
PartOf=gromox-agent.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/alock

[Install]
WantedBy=multi-user.target
