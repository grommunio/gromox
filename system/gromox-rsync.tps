[Unit]
Description=Gromox rsync service
Documentation=man:rsync(8gx) man:rsync.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/rsync

[Install]
WantedBy=multi-user.target
