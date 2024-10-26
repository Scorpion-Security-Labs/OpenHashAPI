# OpenHashAPI Server

OpenHashAPI (OHA) is designed to store and maintain hashes and plaintext in a centralized database. OHA is written in Go and designed for containerized deployment.

OpenHashAPI provides a secure method of communicating hashes over HTTPS and enables lightweight workflows for security practitioners and enthusiasts. OpenHashAPI focuses on extracting value from plaintext and recycles values into newly generated resources such as wordlists, masks, and rules. OHA is designed to target common human password patterns and assess the security of human-generated passwords.

- RESTful API
- JWT Authentication
- HTTPS Communication
- Centralized Database
- Containerized Deployment
- Upload and Search API
- User Administration
- Server Logging
- Quality Control Filtering
- Async Database Validation
- Async Wordlist Generation
- Async Masks Generation
- Async Rules Generation
- Automatic Upload Rehashing
- Remote Download Resource Files
- Multibyte and `$HEX[...]` handling
- Private file hosting
- Browser-based documentation

## Getting Started:
 - [About](#about)
 - [Install](#install)
 - [Usage & API](#usage-&-api)
 - [OpenHashAPI Client](#openhashapi-client)

## About:
- OpenHashAPI was created out of a need to generate hash-cracking materials using
  data. Using discovered material as the foundation for new resources
  often offers better results for security teams. OpenHashAPI provides a method to
  store, quality control, and validate large amounts of hash data.
- The application offers features to upload and store found material as well as
  ensuring material meets quality standards through regex filtering.
- The application features several asynchronous processes to generate new
  material and host it for download. Generated material is sorted by frequency.
- This tool was designed to be used by small-security teams and enthusiasts
  within private networks.

## Install:
- The application is run within a container connected to a database on the
  underlying host.
- The installation is composed of installing and setting up the database, installing
  and setting up the server application, and then deploying the server.
- Instructions can be found within `docs/INSTALL.md`

## Usage & API:
- The API is defined in `docs/API.md` and `docs/API.yml`
- Detailed usage documentation can be found in `docs/FAQ.md`
- The server also supports browser interactive documentation at `/login`

The following are defined API endpoints:
- `/api/register`
- `/api/login`
- `/api/health`
- `/api/found`
- `/api/search`
- `/api/manage`
- `/api/manage/refresh/FILE`
- `/api/status`
- `/api/download/FILE/NUM`
- `/api/lists`
- `/api/lists/LISTNAME`

## OpenHashAPI Client:
- The API can be communicated over HTTPS with any HTTP client
- We offer a recommended client of [OpenHashAPI-Client](#) that can be used to
  seamlessly communicate with the server.
