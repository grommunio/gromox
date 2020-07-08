[Unit]
Description=Gromox SMTP server
Documentation=man:smtp(8gx)
PartOf=gromox-mta.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/smtp

[Install]
WantedBy=multi-user.target
