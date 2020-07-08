[Unit]
Description=Gromox adaptor service
Documentation=man:adaptor(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/adaptor

[Install]
WantedBy=multi-user.target
