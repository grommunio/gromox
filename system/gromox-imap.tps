[Unit]
Description=Gromox IMAP server
Documentation=man:imap(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
# Curb glibc's per-thread malloc arenas in an effort to keep RSS down in the
# face of bursty allocation behavior.
Environment=MALLOC_ARENA_MAX=2
ExecStart=@libexecdir@/gromox/imap
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target
