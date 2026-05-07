[Unit]
Description=The Gromox Information Store
Documentation=man:istore(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/istore
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes
# The systemd default TasksMax (15% of pid_max, might be as low as
# 32768*.15=4915 on plenty of systems) is below what a many-user deployment
# needs.
TasksMax=infinity
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
