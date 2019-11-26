[Unit]
Description=Gromox SMTP server
Documentation=man:smtp(8gx) man:smtp.cfg(5gx)
PartOf=gromox-mta.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/smtp

[Install]
WantedBy=multi-user.target
