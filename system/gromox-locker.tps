[Unit]
Description=Gromox locker service
Documentation=man:locker(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/locker

[Install]
WantedBy=multi-user.target
