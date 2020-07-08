[Unit]
Description=Gromox sensor service
Documentation=man:sensor(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/sensor

[Install]
WantedBy=multi-user.target
