#!/bin/bash

# Install MySQL
# sudo apt update && sudo apt install -y mysql-server && sudo systemctl start mysql.service

# Pre-req for mysql_secure_installation on ubuntu
# STRONGLY suggest changing the default value
# sudo mysql --execute "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';"
# sudo mysql_secure_installation

# Revert auth back so sudo mysql works again
# sudo mysql --execute "ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;"

# Create DB user
# STRONGLY suggest changing the default value
# sudo mysql --execute "CREATE USER 'ohauser'@'localhost' IDENTIFIED BY 'password';"

# Grant user
# NOTE OpenHashAPI.* for database and table permissions
# sudo mysql --execute "GRANT CREATE, ALTER, DROP, INSERT, UPDATE, INDEX, DELETE, SELECT, REFERENCES, RELOAD on OpenHashAPI.* TO 'ohauser'@'localhost';"
# sudo mysql --execute "FLUSH PRIVILEGES;"
echo "please read script before running"
