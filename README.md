
![tests](https://github.com/ghga-de/auth-service/actions/workflows/unit_and_int_tests.yaml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/ghga-de/auth-service/badge.svg?branch=main)](https://coveralls.io/github/ghga-de/auth-service?branch=main)

# GHGA Auth Service

This repository contains two services for the management, authentication and authorization of users of the GHGA data portal.

These two services are described in the following sections. The setting `run_auth_adapter` can be used to determine which of the two services will be started.
## Auth Adapter

The `auth_adapter` subpackage contains the authentication service used by the API gateway via the ExtAuth protocol.

If a `path_prefix` has been configured for the AuthService in the API gateway, then the `api_root_path` must be set accordingly.
## User Management

The `user_management` subpackage contains the user data management service.

## Documentation

An extensive documentation can be found [here](...) (coming soon).

## Quick Start

### Installation

We recommend using the provided Docker container.

A pre-built version is available at [docker hub](https://hub.docker.com/repository/docker/ghga/auth-addapter):

```bash
# Please feel free to choose the version as needed:
docker pull ghga/auth-service:<version>
```

Or you can build the container yourself from the [`./Dockerfile`](./Dockerfile):
```bash
# Execute in the repo's root dir:
# (Please feel free to adapt the name/tag.)
docker build -t ghga/auth-service:<version> .
```

For production-ready deployment, we recommend using Kubernetes, however, for simple use cases, you could execute th service using docker on a single server:
```bash
# The entrypoint is preconfigured:
docker run -p 8080:8080 ghga/auth-service:<version>
```

If you prefer not to use containers, you may install the service from source:
```bash
# Execute in the repo's root dir:
pip install .

# to run the service:
auth-service
```

### Configuration

The [`./example-config.yaml`](./example-config.yaml) gives an overview of the available configuration options.
Please adapt it and choose one of the following options for injecting it into the service:
- specify the path to via the `AUTH_SERVICE_CONFIG_YAML` env variable
- rename it to `.auth_service.yaml` and place it into one of the following locations:
  - the current working directory were you are execute the service (on unix: `./.auth_service.yaml`)
  - your home directory (on unix: `~/.auth_service.yaml`)

The config yaml will be automatically parsed by the service.

**Important: If you are using containers, the locations refer to paths within the container.**

All parameters mentioned in the [`./example-config.yaml`](./example-config.yaml) could also be set using environment variables or file secrets.

For naming the environment variables, just prefix the parameter name with `AUTH_SERVICe_`, e.g. for the `host` set an environment variable named `AUTH_SERVICE_HOST` (you may use both upper or lower cases, however, it is standard to define all env variables in upper cases).

To using file secrets please refer to the [corresponding section](https://pydantic-docs.helpmanual.io/usage/settings/#secret-support) of the pydantic documentation.

## Development

For setting up the development environment, we rely on the [devcontainer feature](https://code.visualstudio.com/docs/remote/containers) of vscode in combination with Docker Compose.

To use it, you have to have Docker Compose as well as vscode with its "Remote - Containers" extension (`ms-vscode-remote.remote-containers`) installed.
Then open this repository in vscode and run the command `Remote-Containers: Reopen in Container` from the vscode "Command Palette".

This will give you a full-fledged, pre-configured development environment including:
- infrastructural dependencies of the service (databases, etc.)
- all relevant vscode extensions pre-installed
- pre-configured linting and auto-formating
- a pre-configured debugger
- automatic license-header insertion

Moreover, inside the devcontainer, there are two convenience commands available (please type them in the integrated terminal of vscode):
- `dev_install` - install the service with all development dependencies, installs pre-commit, and applies any migration scripts to the test database (please run that if you are starting the devcontainer for the first time or if you added any python dependencies to the [`./setup.cfg`](./setup.cfg))
- `dev_launcher` - starts the service with the development config yaml (located in the `./.devcontainer/` dir)

After starting the application with `dev_launcher`, you can access it at the URL http://localhost:8080. You can manage the database using Mongo Express at http://localhost:8088.

If you prefer not to use vscode, you could get a similar setup (without the editor specific features) by running the following commands:
``` bash
# Execute in the repo's root dir:
cd ./.devcontainer

# build and run the environment with docker-compose
docker-compose up

# attach to the main container:
# (you can open multiple shell sessions like this)
docker exec -it devcontainer_app_1 /bin/bash
```

## License

This repository is free to use and modify according to the [Apache 2.0 License](./LICENSE).
