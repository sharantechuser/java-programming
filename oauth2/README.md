## OAuth2

OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to a user's resources on a server. It is widely used for secure and delegated access in various web and mobile applications. In an OAuth 2.0 flow, there are typically two main components: the Authorization Server and the Resource Server.

Here's a high-level overview of how OAuth 2.0 works:

### 1. Authorization Server:

* The Authorization Server is responsible for authenticating the user and obtaining their consent to grant access to the client application.
* It issues access tokens after successful authentication and authorization.
* Examples of Authorization Servers include services like Google, Facebook, or an organization's own OAuth 2.0 server.
### 2. Resource Server:

* The Resource Server hosts the protected resources that the client application wants to access on behalf of the user.
* It verifies the access token presented by the client to determine whether the request should be authorized.
### 3. Client:

* The Client is the application that wants to access the user's resources. It initiates the OAuth 2.0 flow.
### 4. User:

* The end-user is the entity that owns the resources and grants access to them.
## OAuth 2.0 Authorization Grant Types:
OAuth 2.0 defines several grant types for different use cases. The common grant types include:

### 1. Authorization Code Grant:

* Used by web applications.
* Involves a redirect to the Authorization Server, where the user logs in and grants access. An authorization code is then exchanged for an access token.
### 1. Implicit Grant:

* Used by JavaScript or mobile applications.
* Access token is returned immediately after the user grants access, without an additional authorization code exchange.
### 1. Client Credentials Grant:

* Used by confidential clients (e.g., server-to-server communication).
* The client authenticates directly with the Authorization Server using its client credentials to obtain an access token.
### 1. Resource Owner Password Credentials Grant:

* Used when the user trusts the client application with their credentials.
* The client directly obtains the user's username and password to request an access token.
