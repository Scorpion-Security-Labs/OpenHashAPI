- [How Do I Install the Server?](#how-do-i-install-the-server)
- [How Can I Change the Server Configuration?](#how-can-i-change-the-server-configuration)
- [How Do I Communicate with the Server?](#how-do-i-communicate-with-the-server)
- [How Can I Create a User and Login?](#how-can-i-create-a-user-and-login)
- [How Can I Edit User Permissions?](#how-can-i-edit-user-permissions)
- [How Can I Upload Hashes?](#how-can-i-upload-hashes)
- [How Can I Search Hashes?](#how-can-i-search-hashes)
- [How is Data Stored?](#how-is-data-stored)
- [What is Rehashing?](#what-is-rehashing)
- [What is the Quality Filter?](#what-is-the-quality-filter)
- [How Does the Database Self-Heal?](#how-does-the-database-self-heal)
- [How is Data Stored?](#how-is-data-stored)
- [What is Rehashing?](#what-is-rehashing)
- [What is the Quality Filter?](#what-is-the-quality-filter)
- [How Does the Database Self-Heal?](#how-does-the-database-self-heal)
- [How Can I Download Files?](#how-can-i-download-files)
- [How are the Files Made?](#how-are-the-files-made)
- [How Can I See if The Files Are Ready?](#how-can-i-see-if-the-files-are-ready)
- [How Can I Get Different Parts of The Files?](#how-can-i-get-different-parts-of-the-files)
- [How Can I Only Download Content with X in it?](#how-can-i-download-content-with-x-in-it)
- [Are $HEX[...] Items Processed in All Features?](#are-hex-items-processed-in-all-features)
- [Are Multibyte Items Processed?](#are-multibyte-items-processed)
- [The Filter was Changed but Nothing Is Being Removed?](#the-filter-was-changed-but-nothing-is-being-removed)

---
## How Do I Install the Server?
- Steps to install the server are found in `docs/INSTALL.md`

## How Can I Change the Server Configuration?
- The server configuration can be modified using JSON configuration files.
- An example configuration file can be found in `config/config.json`.
- The configuration file location is set in the `Dockerfile`, which is then copied to the container when the application is built.

## How Do I Communicate with the Server?
- The server responds over HTTPS, so any tool that can send HTTP requests can be used.
- API routes are documented in OAS and Markdown in `docs/API.yml` and `docs/API.md`.
- [OpenHashAPI-Client](#) is also recommended to interact with the server deployment.
- In the default configuration, the server uses a self-signed certificate, which may cause errors on some HTTP clients.
- A partial web interface is available at `https://URL/login` and `https://URL/home`.

## How Can I Create a User and Login?
- The easiest way to register is by going to `https://URL/login` and use the form
- The `/api/register` endpoint can be used for user registration. Users can register with the [OpenHashAPI-Client](#).
- The `/api/register` endpoint must be enabled in the `config.json` file for users to self-register to the application.
- After registering an account, the `/api/login` endpoint can retrieve a valid authentication token. 
- The application uses the `Authorization: Bearer <JWT>` HTTP header to authenticate requests.
- Server administrators can disable specific users from authenticating using `/api/manage`.

## How Can I Edit User Permissions?
- User permissions can be edited through the `/api/manage` endpoint.
- By default, user accounts do not have permission to modify their or other user's permissions.
- To grant this permission the first time, please edit the database manually.
    - `UPDATE Users SET can_manage = 1 WHERE id = 0;`
- The following permissions can be used to restrict users access:
    - `canLogin`
    - `canSearch`
    - `canUpload`
    - `canManage`
    - `canViewPrivateLists`
    - `canEditPrivateLists`

## How Can I Upload Hashes?
- Authenticated users are allowed to submit new hashes to the database.
- This can be done with the `/api/found` endpoint.
- Uploaded hashes will be affected by the `quality-filter` and the `rehash` feature if set.
- Server administrators can disable specific users from uploading using `/api/manage`.
- If server administrators allow, files not
  affected by filtering or database can also be uploaded. These files are stored in the container's filesystem and can be updated with new findings.
- The `/api/lists` and `/api/lists/LISTNAME` endpoints accept GET and POST
  requests to work with private lists.

## How Can I Search Hashes?
- Authenticated users can search the database for hashes or plaintext values.
- This can be done with the `/api/search` endpoint.
- Searched hashes or plaintext will cover all algorithms and retrieve matching entries.
- Server administrators can disable specific users from searching using `/api/manage`.

## How is Data Stored?
- Data is stored within two tables: `Hashes` and `Users`
- `Users` contains each registered user's username, hash, and permissions matrix.
- `Hashes` contains the algorithm, hash, and plaintext for each submitted hash.
- Hashes are accepted as `HASH:PLAIN` or `HASH:SALT:PLAIN` values, and attempts are made to parse plaintext from hash values.
- If private lists are allowed, these are stored on the container's filesystem and can be mounted to the host for persistence.
- Within the container, files are stored within the `/var/www/OpenHashAPI` directory and contain the following:
    - `lists/`
    - `logs/`
    - `static/`
    - `templates/`

## What is Rehashing?
- Rehashing is a feature that allows uploads to be automatically rehashed into MD5 (0), SHA1 (100), or NTLM (1000).
- By enabling rehashing, the original `HASH:PLAIN` will not be stored, and only the rehashed version will be stored.
- Rehashing will use the plaintext value and `$HEX[...]` plaintexts are decoded before rehashing.
- Rehashing can be turned on or off within `config.json`.

## What is the Quality Filter?
- Quality filtering is a feature that allows the server administrator to reject plaintexts that match a regex pattern.
- This feature is used when uploading hashes and when the database is self-healing.
- If uploading, items that match the filter will be rejected and not stored within the database.
- If self-healing, items already in the database will be deleted.
- Items in `$HEX[...]` format are decoded before comparing.
- Quality filtering can be turned on or off within `config.json`.

## How Does the Database Self-Heal?
- Self-healing or self-validation is a feature that allows the database to validate entries within the database asynchronously for quality and accuracy.
- Self-healing requires the rehashing feature also to be enabled.
- When the server starts, a process will start to enumerate the database and look for incorrect `HASH:PLAIN` combinations and items that the quality filter can catch.
- When an item is validated, it is marked as `true` in the `validated` column of the `Hashes` table.
- The number of chunks the database is divided into, and the number of workers assigned to enumerate the chunks can be configured in `config/config.json.`
- Self-healing can be turned on or off within `config.json`.

## How Can I Download Files?
- Authenticated users are allowed to download files created by the server.
- This can be done with the `/api/download/FILE/NUM` endpoint.
- `FILE` can be one of three values: wordlist, masks, and rules.
- `NUM` must be a valid integer value, and the query will return that many rows.
- If private lists are allowed, the `/api/lists/LISTNAME` endpoint can be used to retrieve content.

## How are the Files Made?
- Files are made asynchronously from the database records and made ready for download.
- The wordlist is made using the database records to extract base words.
- The masks are made using the database records to extract masks that meet minimum complexity requirements.
- The rules are made by using the database records to extract features from plaintext to generate rules.
- All files are sorted by occurrence.
- Each file type can be turned on or off in `config/config.json`.
- To edit the logic, functions are found in `internal/config/config.go`.

## How Can I See if The Files Are Ready?
- Because the files are generated asynchronously, they can take time to prepare.
- The `/api/status` endpoint allows unauthenticated users access to view the status of the file generation and if they are available for download.

## How Can I Get Different Parts of The Files?
- The `NUM` variable in the path can control the number of lines returned.
- The query string `offset` can be added to control where the starting point is for retrieving lines.
- For example, `/api/downloads/wordlist/1000?offset=1000` will take 1,000 rows starting at the 1,000th row.

## How Can I Only Download Content with X in it?
- The query string `contains` can be added to control the type of content returned.
- This will only return rows that contain the substring in `contains`.
- For example, `/api/downloads/wordlist/1000?contains=test` will take 1,000 rows that contain "test".
- Additonal query strings of `append`, `prepend`, and `toggle` can also be added for rule queries to only fetch certain rules. A boolean value is used to control these.

## Are $HEX[...] Items Processed in All Features?
- Yes, `$HEX[...]` items are decoded before being used by many features that rely on plaintext values.

## Are Multibyte Items Processed?
- Yes, multibyte items are processed by the application.
- To ensure valid rules, multibyte items are transformed for the rule generation process.

## The Filter was Changed, but Nothing is Being Removed.
- Once items are marked as validated in the `Hashes` database table, they need to
  be reset to `false` to be rescanned by new filters.
- Once items are reset, the self-validation feature will enumerate them and
  remove any that match the new filter.

