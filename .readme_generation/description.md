<!-- Please provide a short overview of the features of this service. -->

This repository contains two services for the management, authentication and authorization of users of the GHGA data portal.

These two services are described in the following sections. The setting `run_auth_adapter` can be used to determine which of the two services will be started.

### Auth Adapter

The `auth_adapter` sub-package contains the authentication service used by the API gateway via the ExtAuth protocol.

If a `path_prefix` has been configured for the AuthService in the API gateway, then the `api_root_path` must be set accordingly.

Note that the Auth Adapter carries out a dual role in our architecture, by communicating directly with the client in order to establish user sessions and enroll TOTP, and also regulating access to the backend while modifying authorization headers. This utilises the [ExtAuth](https://www.getambassador.io/docs/edge-stack/latest/topics/running/services/ext-authz) protocol used by Envoy-based proxies like Emissary-ingress. It does not work with Nginx-based proxies like Ingress-Nginx, because the protocol for external authentication used by `http_auth_request_module` works in a slightly different way that prevents this dual-use of the Auth Apater.

Emissary-ingress does not forward all authorization headers by default, therefore the additional headers must be configured for the `AuthService` like this:

```yaml
  allowed_request_headers:
  - x-authorization
  - x-csrf-token
  allowed_authorization_headers:
  - cookie
  - x-authorization
  - x-csrf-token
  - x-session
```

The `x-authorization` header is only needed when an additional HTTP Basic Auth is used on top of the OIDC based authentication. Only the default `authorization` header actually needs to be modified by the Auth Adapter. However, for security purposes the Auth Adapter also empties the authorization headers that it consumes and evaluates itself and which are therefore not needed by the backend. Therefore, these are also specified as response headers.

### User Management

The `user_management` sub-package contains the user data management service.

The user management contains two APIs, the `users` API for the user registry, and the `claims` API for the claims repository. The setting `include_apis` can be used to specify which of the two APIs should be provided. For testing purposes, both APIs can be provided at the same time, but this is not recommended in production.
