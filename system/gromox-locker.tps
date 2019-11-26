[Unit]
Description=Gromox locker service
Documentation=man:locker(8gx) man:locker.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/locker

[Install]
WantedBy=multi-user.target
