[Unit]
Description=Gromox synchronizer service
Documentation=man:synchronizer(8gx) man:synchronizer.cfg(5gx)
PartOf=gromox-da.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/synchronizer

[Install]
WantedBy=multi-user.target
