### Installing the Database:
- [Installing the Database Software](#installing-the-database-software)
- [Securing the Database Installation](#securing-the-database-installation)
- [Create the Database and Tables](#create-the-database-and-tables)
- [Create the Database User](#create-the-database-user)

### Installing the Server:
- [Install the Container Software](#install-the-container-software)
- [Create the Configuration File](#create-the-configuration-file)
- [Build the Docker Image](#build-the-docker-image)
- [Deploy the Server Image](#deploy-the-server-image)

### Setting up a New Instance:
- [Register a New User](#register-a-new-user)
- [Assign Initial Permissions](#assign-initial-permissions)
- [Create Routine Backups](#create-routine-backups)

### Common Issues:
- [Issues Running mysql_secure_installation](#issues-running-mysql_secure_installation)
- [Issues Installing Docker](#issues-installing-docker)

---

### Installing the Database Software
The database is installed on the underlying host to provide data persistence, and the application runs within a container on the host system. The first step is to ensure that MySQL is installed and running.

```
sudo apt update && sudo apt install -y mysql-server && sudo systemctl start mysql.service
```
> [!TIP]
> Some distros have MySQL/MariaDB installed by default. Check with `sudo systemctl status mysql && sudo systemctl start mysql.service`.

The intructions will also be done in the following screen captures. We will start with a fresh install of Ubuntu 22.04.3 LTS:

![Screen capture of a terminal running uname and installing mysql with apt.](/docs/images/install-1.png)
---

### Securing the Database Installation
With `mysql` installed, we want to reconfigure the database to be more secure by default. Some distributions may not be able to run the following command, if so, please see [Common Issues](#issues-running-mysql_secure_installation).

```
sudo mysql_secure_installation
```
> [!TIP]
> Having issues? See [Common Issues](#issues-running-mysql_secure_installation)

The following shows running `mysql_secure_installation` after installing MySQL with `apt`. For this process select "Y" or "y" for all settings to secure the MySQL installation. For the password requirement, we would suggest using the strongest value available.

![Screen capture of running the mysql_secure_installation command in a terminal.](/docs/images/install-3.png)
---

### Create the Database and Tables
With `mysql` configured, the next step is configuring the database and associated tables. 

> [!TIP]
> In `config/examples` there are two scripts that can be used to create the database and replicate the following commands. They can be used with `cat create_database.sql | mysql (-u root -p)`.

Suggest running these directly in `mysql`:
```
sudo mysql
```

Create the database `OpenHashAPI`, the table `Hashes`, and the table `Users`:
```
CREATE DATABASE OpenHashAPI;
USE OpenHashAPI;

CREATE TABLE Hashes (
  algorithm      VARCHAR(8) NOT NULL,
  hash     VARCHAR(255) NOT NULL,
  plaintext     VARCHAR(255) NOT NULL,
  validated     BOOLEAN DEFAULT FALSE,
  PRIMARY KEY (`algorithm`, `hash`)
);

CREATE TABLE Users (
    id    int NOT NULL AUTO_INCREMENT,
    username            VARCHAR(32) NOT NULL,
    password            VARCHAR(255) NOT NULL,
    can_login           BOOLEAN NOT NULL,
    can_search          BOOLEAN NOT NULL,
    can_upload          BOOLEAN NOT NULL,
    can_manage          BOOLEAN NOT NULL,
    can_view_private    BOOLEAN NOT NULL,
    can_edit_private    BOOLEAN NOT NULL,
    PRIMARY KEY (`id`, `username`)
);

ALTER TABLE Users ADD UNIQUE (username);
exit
```

The commands can be executed as a MySQL script or directly through the command line. In the following screen capture, we enter the commands directly into the `mysql` console.

![Screen capture of a mysql terminal running the commands to create the database.](/docs/images/install-4.png)
---

### Create the Database User
Next, we will need a lower privilege database user named `ohauser` for the application. Ensure you have exited `mysql`.

> [!IMPORTANT]
> The password for the database user is validated to be at least 12 characters and meet complexity requirements which require at least one lower, upper, digit, and special character.

```
sudo mysql --execute "CREATE USER 'ohauser'@'localhost' IDENTIFIED BY 'password';"
```
> [!TIP]
> Please set a secure password between 12 and 18 characters. This account will be associated with the database.

Lastly, we will give them permissions over the database and apply those privileges:
```
sudo mysql --execute "GRANT CREATE, ALTER, DROP, INSERT, UPDATE, INDEX, DELETE, SELECT, REFERENCES on OpenHashAPI.* TO 'ohauser'@'localhost';"
```
```
sudo mysql --execute "FLUSH PRIVILEGES;"
```

The following commands will create a user and configure appropriate permissions to interact with the database then apply them. Please set a secure password when configuring this account as it will be associated with the backend database. The image also shows the next step of installing Docker. 

![Screen capture of a terminal using the mysql command to configure a user and install docker.](/docs/images/install-5.png)
---

### Install the Container Software

The application is run in a containerized environment. To do this, we will need `Docker`:
```
sudo apt update && sudo apt install -y docker.io
```

> [!NOTE]
> [Offical install documentation](https://docs.docker.com/engine/install/) (external link)

---

### Create the Configuration File

The server uses a JSON configuration file to set several variables used by the server:
* `DatabaseUser`: The username of the database user.
* `DatabasePwd`: The password of the database user.
* `AuthenticationPepper`: The pepper value used in authentication.
* `DatabaseIdleConnections`: The number of idle database connections allowed.
* `ServerPort`: The port the server will host on.
* `ServerTLSCertfilePath`: Local path to the cert file for TLS.
* `ServerTLSKeyfilePath`: Local path to the key file for TLS.
* `ServerJWTPublicPEMfilePath`: Local path to the public PEM file for auth.
* `ServerJWTPrivatePEMfilePath`: Local path to the private PEM file for auth.
* `ServerJWTTimeToLive`: The JWT auth token TTL value.
* `ServerGBMaxUploadSize`: Max POST request size in GB.
* `OpenRegistration`: If users are allowed to self-register accounts.
* `RehashUploads`: If uploads should be rehashed into another algorithm.
* `RehashAlgorithm`: The algorithms to use are 0, 100, and 1000.
* `QualityFilter`: If uploads should be filtered before adding to the database.
* `QualityFilterRegex`: Regex to match bad items to.
* `SelfHealDB`: If the database should validate hashes in the background.
* `SelfHealDBChunks`: Number of chunks the database is broken into for the worker pool.
* `SelfHealDBWorkers`: Number of workers to spawn for the validation process.
* `GenerateWordlist`: If the server should start a process to make a wordlist.
* `GenerateRules`: If the server should start a process to make a rule list.
* `GenerateMasks`: If the server should start a process to make a mask list.
* `AllowUserLists`: If the server should allow the creation and downloading of user lists.

> [!IMPORTANT]
> **Ensure that the `open-registration` parameter is set; otherwise, registration will be closed!**
> **Ensure that the `database-pwd` parameter is set; otherwise, you will not be able to login!**

The configuration file can be found in `config/config.json` and looks like the following:
```
{
    "database-user":"ohauser",
    "database-pwd":"password",
    "auth-pepper":"0H4St4ticP3pp3r",
    "database-idle-connections":100,
    "server-port":8080,
    "server-tls-certfile-path":"server.crt",
    "server-tls-keyfile-path":"server.key",
    "server-jwt-public-pemfile-path":"public_key.pem",
    "server-jwt-private-pemfile-path":"private_key.pem",
    "server-jwt-ttl":15,
    "server-gb-max-upload-size":2,
    "open-registration":true,
    "rehash-uploads":true,
    "rehash-algorithm":0,
    "quality-filter":false,
    "quality-filter-regex":"(xiaonei|zomato|fbobh|fccdbbcdaa)|http:\\/\\/|https:\\/\\/|\\@.*\\.net|<tr>|<div>|<a href|<p>|<img src|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}|^[0-9]+$|^.{0,5}$"
    "self-heal-database":true,
    "self-heal-database-chunks":1000,
    "self-heal-database-workers":10,
    "generate-wordlist":true,
    "generate-rules":true,
    "generate-masks":true,
    "allow-user-lists":true
}
```
> [!TIP]
> Consider changing the authentication pepper to a unique value per install. This value will be used in authentication hash security. Pepper must be at least 8 characters long and contain a mix of uppercase, lowercase letters, and at least one digit and one special character. Changing this to a custom value will increase the offline security of any compromised user's password hash due to the tool being open source.

If we `git clone` the repository we can use the configuration file found in `/config/config.json` as a base.
![Screen capture of a terminal using vim to edit the configuration file.](/docs/images/install-6.png)

Configure this file with the updated settings, including the database username and password and then ensure that the `Dockerfile` is pointed at the correct configuration file:
```
# Location of your config file
ENV CONF_FILE=./config/config.json
COPY ${CONF_FILE} /etc/config.json
```

> [!IMPORTANT]
> **Ensure you have updated the password for the database user and open-registration is enabled before building!**

After editing the configuration file, ensure that the paths for the configuration file, as well as any other items like custom certificates, are correctly stated before building the image.

![Screen capture of a terminal using vim to edit the Dockerfile to ensure the correct paths are set.](/docs/images/install-7.png)
---

### Build the Docker Image

Next, we can build the image containing the server application and configuration.
- Ensure you are in the same directory as the `Dockerfile` or point it to the correct path.
```
sudo docker build -t ohaserver .
```

---

### Deploy the Server Image

With everything configured correctly, we should be able to start the container on the host running the database.
```
 sudo docker run --rm -it --net=host ohaserver
```

![Screen capture of a terminal using docker to build and run the image.](/docs/images/install-8.png)
---

### Register a New User
There are two options for registering a new user:
- The easiest way to register is by going to `https://URL/login` and use the form
- The other way is to send a formatted request to `/api/register` with the client

> [!IMPORTANT]
> Ensure that the `open-registration` parameter is set otherwise registration will be closed.

In the capture below, we can see using a browser to register a new user with a complex password (at least 12 characters long and contain a mix of uppercase, lowercase letters, and at least one digit and one special character).
![Screen capture of a terminal and a browser showing the new user registration process](/docs/images/install-9.png)

After this step you should be able to login and test most of the API endpoints.
![Screen capture of a terminal and a browser showing a successful login](/docs/images/install-10.png)

> [!NOTE]
> This will be the user you authenticate to the platform and API with! If using the `OpenHashAPI` client, ensure that the username and password field is updated.

Once this step is completed, the `OpenHashAPI` server should be ready to use, consider testing the upload portion by submitting the example hash to the database.
```
curl -X POST \
      https://192.168.40.162:8080/api/found \
      -H 'Authorization: Bearer THE_JWT_VALUE' \
      -H 'Content-Type: application/json' \
      --data '{
        "algorithm": "0",
        "hash-plain": [
            "5f4dcc3b5aa765d61d8327deb882cf99:password"
            ]
        }'
```

> [!NOTE]
> The API will be looking for an array of strings containing atleast one ":". Hashes should be in `HASH:PLAIN` or `HASH:SALT:PLAIN` and the `algorithm` should be an integer value reflecting the hash mode used.

---

### Assign Initial Permissions
New users, by default, do not have the `canManage` permission and can not use `/api/manage`. A newly created Administrator user must be assigned this permission before using the API endpoint.

```
sudo mysql
use OpenHashAPI;
UPDATE Users SET can_manage = 1 WHERE id = 0;
```

> [!TIP]
> Update the value of `id` with your created users. You can find the ID value with `SELECT * FROM Users;`

---

### Create Routine Backups
Once everything is set up, strongly consider creating routine backups of the
primary database.

Backups can be created with the following script:
```
#!/bin/bash

date=$(date +"%m-%d-%Y")
mysqldump --databases --single-transaction --quick OpenHashAPI > $date-oha.sql
```

### Common Issues

#### Issues Running `mysql_secure_installation`

On Ubuntu systems, you may need to reconfigure the default authentication mechanism first:
```
# STRONGLY suggest changing the password value
# This command will allow for "mysql_secure_installation" to work by setting the root account with a native password
sudo mysql --execute "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';" && sudo mysql_secure_installation

# Revert auth back so sudo mysql works again and remove the native password
sudo mysql -u root -p --execute "ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;"
```

The commands above will allow the `root` account to authenticate with `sudo`. If you do not set this up you may have to use `-u root -p` syntax instead:
```
sudo mysql -u root -p
```

This syntax will be needed for the entire installation process pirot to the `--execute` commands.

### Issues Installing Docker 

Docker can have different installation requirements based on the underlying
host operating system. These instructions will not be consistent for every
installation so please refer to the offical Docker installation documentation
for any issues.

- [Offical install documentation](https://docs.docker.com/engine/install/) (external link)

