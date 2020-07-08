[Unit]
Description=Gromox HTTP service
Documentation=man:http(8gx)
PartOf=gromox-exch.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/http

[Install]
WantedBy=multi-user.target
