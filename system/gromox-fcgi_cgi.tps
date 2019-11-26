[Unit]
Description=Gromox fcgi_cgi service
Documentation=man:fcgi_cgi(8gx) man:fcgi_cgi.cfg(5gx)
PartOf=gromox-da.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/fcgi_cgi

[Install]
WantedBy=multi-user.target
