## Known Security Issues and Discussion

### Secret Material Compromise By Lower Privilege Container User
- In the event a user is able to access the underlying container being used by
  OpenHashAPI, the secret material stored will be readable by the `nonroot`
  user.
- This means that the environmental variables, PEM files, and certificates used
  for TLS and JWT *will* be compromised in the event someone were to compromise
  the `nonroot` user on the container.
- **Advisory:** In the event of compromise, restart the container and remove
  any persistent images and rotate secrets stored in the `config.json` file.
  In the default version of OpenHashAPI, the PEM keys and TLS certificates are
  generated new every run unless the container was not started with `--rm`. If
  the `Dockerfile` was modified to use other secret material, ensure that
  material is rotated for all affected devices. Restore the back-end database
  to prior versions to ensure no persistent accounts were created. Assume
  hashes have been compromised and reset the authentication pepper.

### User Lists Permissions and Default File View/Edit Visibility
- The ability to allow or deny user lists to be uploaded, edited, or viewed is
  done with the `allow-user-lists` setting in `config.json` set on the
  server.
- The ability to restrict users to view lists is done with the
  `canViewUserLists` user permission which is tied to the `can_view_private`
  permission in the `Users` database table.
- The ability to restrict users to edit lists is done with the
  `canEditUserLists` user permission which is tied to the `can_edit_private`
  permission in the `Users` database table.
- By default, all users with these permissions will be able to see and edit the
  same files. This means that by default, a user with these permission will be
  able to see and edit **all** files respectively. There is no notion of
  per-list restricted access within the application at this time. 
