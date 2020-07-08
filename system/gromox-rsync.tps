[Unit]
Description=Gromox rsync service
Documentation=man:rsync(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/rsync

[Install]
WantedBy=multi-user.target
