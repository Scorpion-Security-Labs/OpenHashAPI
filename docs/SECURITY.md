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
  to prior versions to ensure no persistent accounts were created.
