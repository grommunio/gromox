[Unit]
Description=Gromox timer service
Documentation=man:timer(8gx) man:timer.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/timer

[Install]
WantedBy=multi-user.target
