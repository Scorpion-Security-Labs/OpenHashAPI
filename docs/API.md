# OpenHashAPI

## Authentication Endpoints

### POST `/api/register`
- Registers a new user.
- Authenticated: `false`
- Query Params: `none`
- Access Role: `open-registration` in server configuration 
- Request Body:
    * `username`: The username of the new user.
    * `password`: The password of the new user.
### POST `/api/login`
- Logs in a user.
- Authenticated: `false`
- Query Params: `none`
- Access Role: `canLogin` in user attributes 
- Request Body:
    * `username`: The username of the user logging in.
    * `password`: The password of the user logging in.

## Usage Endpoints

### GET `/api/health`
- Fetches information about the server-side configuration.
- Authenticated: `true`
- Query Params: `none`
- Access Role: `none` 
### POST `/api/found`
- Submits new material to the database through the API.
- Authenticated: `true`
- Query Params: `none`
- Access Role: `canUpload` in user attributes 
- Request Body:
    * `algorithm`: The algorithm used to generate the hash.
    * `hash-plain`: An array of hashes and plain text values.
    * Values should be submitted as `HASH:PLAIN` or `HASH:SALT:PLAIN`
    * The `algorithm` parameter should be an integer representing the hash mode.
### POST `/api/search`
- Allows searching the database by either `hash` or `plain` values.
- Authenticated: `true`
- Query Params: `none`
- Access Role: `canSearch` in user attributes 
- Request Body:
    * `data`: An array of hashes or plain text values to search for.
### POST `/api/manage`
- Allows for the permission management of other users.
- Authenticated: `true`
- Query Params: `none`
- Access Role: `canManage` in user attributes 
- Request Body:
    * `userID`: The user's ID to manage permissions for.
    * `canLogin`: Whether the user can log in.
    * `canSearch`: Whether the user can search the database.
    * `canUpload`: If the user can upload new material to the database.
    * `canManage`: Whether the user can manage other users' permissions.
    * `canViewUserLists`: If the user can view user lists on the server.
    * `canEditUserLists`: Whether the user can edit user lists on the server.
### GET `/api/download/FILE/NUM`
- Allows the download of files from the server.
- FILE can be wordlist, mask, or rules. NUM is the number of results to return.
- Authenticated: `true`
- Query Params: `offset` `contains`
- Access Role: `none` 
- Parameters:
    * `FILE`: The name of the file to download.
    * `NUM`: The number of rows to download.
- Query String Parameters:
    * `offset`: Will return results starting at Nth position.
    * `contains`: Will only return results that contain a substring.
    * `prepend`: Will only return results that do or do not contain prepend rules.
    * `append`: Will only return results that do or do not contain append rules.
    * `toggle`: Will only return results that do or do not contain toggle rules.
- Responses:
    * `200`: OK
    * `Content-Type`: `application/octet-stream`
    * Body: The contents of the file.
### GET `/api/status`
- Returns the status of the downloadable files from the server.
- Authenticated: `false`
- Query Params: `none`
- Access Role: `none` 
- Responses:
    * `200`: OK
    * `Content-Type`: `application/json`
    * Body:
        * `status`: The status of the server.
        * `files`: An array of files and their sizes.

### GET `/api/lists` & GET `/api/lists/LISTNAME`
- Fetches information about or returns content of any downloadable files stored on the server.
- The `LISTNAME` parameter is the file to return contents of.
- Authenticated: `true`
- Query Params: `none`
- Access Role: `canViewUserLists` in user attributes and `allow-user-lists` in server configuration
- Responses:
    * `200` OK
    * `Content-Type`: `text/plain`
    * Body:
        * Content of the file or success message

### POST `/api/lists` & POST `/api/lists/LISTNAME`
- Creates a new list or updates a posted list with new items. 
- The `LISTNAME` parameter will attempt to update that file with new items.
- Authenticated: `true`
- Query Params: `name`
- Access Role: `canEditUserLists` in user attributes and `allow-user-lists` in server configuration
- Responses:
    * `200` OK
    * `Content-Type`: `text/plain`
    * Body:
         * Success message
