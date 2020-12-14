# <a id="top"></a>openid-client-helper

An extension to [openid-client](https://www.npmjs.com/package/openid-client) for automated maintenance and transparent application of [OAuth 2.0](https://tools.ietf.org/html/rfc6749) access tokens.

```javascript
const Helper = require('openid-client-helper')

const {
  authorize,
  fetch,
  . . .
} = Helper(params)

router.get('/authorize', authorize(), (req, res) => {
  fetch(
    'https://oauth2-protected-resource',
    options,
    req
  )
  . . .
}
```

See [How To Make It Work](#how-to-make-it-work) for details.

## <a id="contents"></a>Contents

* [Motivation](#motivation)
* [Features](#features)
* [How It Works](#how-it-works)
* [How To Make It Work](#how-to-make-it-work)
* [API Reference](docs/README.md)
* [Examples](#examples)

## <a id="motivation"></a>Motivation

[Back to top](#top)

The openid-client library provides components for building a [Node.js](https://nodejs.org/en/) application acting as an OAuth 2.0 [client](https://tools.ietf.org/html/rfc6749#section-1.1) extended to an [OpenID Connect](https://openid.net/connect/) (OIDC) [Relying Party](https://openid.net/specs/openid-connect-core-1_0.html#Terminology). When using openid-client by itself, it is left up to the developer to implement routes for each REST API call authorized by an access token.

The openid-client-helper library provides a [node-fetch](https://www.npmjs.com/package/node-fetch) wrapper for making requests to different resources protected by the same [authorization server](https://tools.ietf.org/html/rfc6749#section-1.1). Each request is automatically crafted with a fresh, resource-specific access token appropriate for the requested URI.

After initial authorization by the [resource owner](https://tools.ietf.org/html/rfc6749#section-1.1), access tokens for individual resources are obtained with a [refresh token](https://tools.ietf.org/html/rfc6749#section-1.5), entirely via a secure back-channel, without any further resource owner involvement and not relying on their saved consent, and not collecting the resource owner password credentials.

This means that the client, once authorized, will be able to perform API requests with automatically obtained individually-scoped and potentially [Audience Restricted](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-14#section-4.8.1.1.3) access tokens—according to the [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-14) (BCP). This also means that the format and the content of the access tokens can be specific to the respective resource servers.

In addition, openid-client-helper provides convenience methods for performing OAuth 2.0 [authorization code](https://tools.ietf.org/html/rfc6749#section-1.3.1) grant, deauthorization, and accessing [ID Token Claims](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) about the resource owner.

## <a id="features"></a>Features

[Back to top](#top)

* OAuth 2.0 authorization and OIDC authentication [Express.js](https://expressjs.com/) middleware
* Deauthorization and [RP-Initiated Logout](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout) Express.js middleware
* Automatic acquisition and renewal of access tokens for each configured resource
* Automatic addition of a resource-specific access token in fetch requests made to a protected API
* Convenience methods allowing direct access to the authorization data and ID Token claims
* Easy setup for different [OpenID provider](https://openid.net/specs/openid-connect-core-1_0.html#Terminology) and relying party combinations
* Based on the openid-client library
* Can work alongside Express.js and Passport.js

## <a id="how-it-works"></a>How It Works

[Back to top](#top)

The openid-client-helper library is represented by a CommonJS module, which exports a constructor function. The constructor function takes a set of parameters including openid-client [Issuer](https://github.com/panva/node-openid-client/tree/master/docs#issuer) and [Client](https://github.com/panva/node-openid-client/tree/master/docs#client) metadata, so that the instance can act as a client or a relying party. If a set of resources is provided as the `resources` parameter, it will be used to obtain and apply resource-specific, potentially audience-restricted access tokens. Additional parameters could be included to change the helper's default behavior regarding the use of [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636) (PKCE) and [Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707), whether the resource owner approved "master" access token should be used as a substitute for failing resource-specific tokens, and how the user session object is identified. The constructor will also accept a function to apply customizations to the underlying openid-client functionality.

The `resources` parameter is intended to contain a set of protected resources each of which is associated with the resource-specific OAuth 2.0 [scope](https://tools.ietf.org/html/rfc6749#section-3.3). Optionally, a resource identifier can be added as the [resource](https://tools.ietf.org/html/rfc8707#section-2) parameter to the resource-specific token requests, making it available for the systems adopting Resource Indicators for OAuth 2.0. The scope property associated with the resource will be included as the `scope` parameter in the resource-specific token request, allowing to derive the audience restriction from a unique scope.

> Even if true audience restriction could not be expressed via a unique scope, restricting an access token to a subset of the scopes authorized by the resource owner may still be beneficial when one of the [resource servers](https://tools.ietf.org/html/rfc6749#section-1.1) gets compromised, and if the scopes for different resource servers do not completely overlap.

The helper instance supplies Express.js middleware for performing the authorization code grant. If the instance methods are used in the authorization process, the authorization results are captured automatically. In addition, the resulting from OIDC authentication flow ID token is preserved by the helper instance as well, and its claims become available to the client application via a publicly-exposed convenience method.

> The main objective of this library is maintaining authorization state that can be used for making HTTP requests to resources protected by OAuth 2.0 on behalf of the resource owner. The authorization code grant is the only recommended OAuth 2.0 flow for a typical web application, where the client software is directly interacting with the user-agent. As implementing this grant seems to be a common task a web application developer may face, the helper allows to do it with minimal effort.
>
> The underlying openid-client functionality expects ID token to be present. Hence, the OIDC authentication is always requested via the `openid` scope during the authorization request.

Alternatively, the authorization may be obtained with external tools; for example, with the openid-client [Passport.js strategy](https://github.com/panva/node-openid-client/tree/master/docs#strategy). Then, the authorization results could be added to the helper instance manually, by utilizing its public interface.

The helper's token management functionality relies on presence of a refresh token authorized with all the scopes required by the resources collectively. The main benefit of using a refresh token in this case is the option to perform partial, resource-specific authorization via the back-channel, with no assistance or saved consent from the resource owner, and no user-agent involvement.

> If you need to manage resource-specific access tokens in the browser, you may consider the [appAuthHelper](https://www.npmjs.com/package/appauthhelper) library, which can be used with a [public OAuth 2.0 client](https://tools.ietf.org/html/rfc6749#section-2.1) in a [SPA](https://en.wikipedia.org/wiki/Single-page_application).

However it is obtained, the refresh token could be saved in a helper instance and serve as inexhaustible source of access tokens specially minted for the respective resource server, until the refresh token itself is expired or revoked. The authorized helper instance can be used then as a "fetch proxy" for requests made to APIs protected by OAuth 2.0.

For this, openid-client-helper provides redefined node-fetch `fetch` method. If this method is used, each fetch request will be crafted with a specific to the requested resource access token. The resource will be identified by matching the requested URI. If necessary, the access token will be automatically obtained or renewed while handling the request. If no access token can be obtained for a particular resource, the request will be passed through to the underlying node-fetch method unchanged.

> For separately maintained resource servers, implementing access token audience and scope restriction has been recommended by the [OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750#section-5.2) standard, the OIDC [core specs](https://openid.net/specs/openid-connect-core-1_0.html#AccessTokenRedirect), and the [OAuth 2.0 Security BCP](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-14#section-2.3).

## <a id="how-to-make-it-work"></a>How To Make It Work

[Back to top](#top)

* [Install](#installation)
* [Import](#how-to-make-it-work-import)
* [Configure](#how-to-make-it-work-configure)
* [Authorize](#how-to-make-it-work-new-authorization)
* [Use Existing Authorization](#how-to-make-it-work-existing-authorization)
* [Fetch](#how-to-make-it-work-fetch-protected-resource)
* [Check If Authorized](#how-to-make-it-work-check-if-authorized)
* [Deauthorize](#how-to-make-it-work-deauthorize)

### <a id="installation"></a>Install

[Back](#how-to-make-it-work)

```bash
npm install openid-client-helper
```

### <a id="how-to-make-it-work-import"></a>Import

[Back](#how-to-make-it-work)

```javascript
const OpenIdClientHelper = require('openid-client-helper')
```

### <a id="how-to-make-it-work-configure"></a>Configure

[Back](#how-to-make-it-work)

A helper instance can be created by providing an authorization server/OpenID provider and a client/relying party metadata and a set of resources to manage.

You will need to supply enough metadata for constructing a valid and functional openid-client [Issuer](https://github.com/panva/node-openid-client/tree/master/docs#issuer). This configuration information can be provided manually or, preferably, retrieved from the `.well-known` Discovery URI, as described in [Obtaining OpenID Provider Configuration Information](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) in the OIDC docs. In the latter case, the well-known URI would serve as the issuer identifier and could be the only parameter of issuer metadata to be provided in the configuration. For example:

```javascript
const issuerMetadata = {
  issuer: 'https://example.com/oauth2'
}
```

If some of the necessary metadata is missing from the discovery document, it could be added manually. For example:

```javascript
issuerMetadata.revocation_endpoint = 'https://example.com/oauth2/token/revoke'
```

You will also need to describe an openid-client [Client](https://github.com/panva/node-openid-client/tree/master/docs#client) and, at very minimum, specify its OAuth 2.0 client ID and the way it authenticates to the Issuer. Normally, you'd also need to provide information about redirection URIs registered with the authorization server. For example:

```javascript
const clientMetadata = {
  client_id: 'client-id',
  client_secret: 'client-secret',
  token_endpoint_auth_method: 'client_secret_post', // The default is 'client_secret_basic'.
  redirect_uri: 'http://localhost:3333/redirect',
  post_logout_redirect_uri: 'http://localhost:3333'
}
```

Then, specify resources that will need to be authorized and are protected by the Issuer. For example:

```javascript
const resources: {
  'https://protected-resource-uri-1': {
    scope: 'scope-1 scope-2'
  },
  'https://protected-resource-uri-2': {
    scope: 'scope-3 scope-4'
  }
}
```

A resource key does not have to be the full URI of a protected endpoint. It may contain only the left part sufficient for identifying one or more URIs protected by the same access token—that is, an access token formatted for and associated with the same resource and/or issued the same scope. When a fetch request comes in, its `url` parameter will be compared with resource keys provided in the configuration object. The resource key that most closely matches the requested `url`, will be used to retrieve the corresponding access token.

> A resource key can be described as the [resource](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08#section-2) parameter proposed in the Resource Indicators for OAuth 2.0 draft. An openid-client-helper instance created with the `useResourceIndicators` parameter assigned a `true` value (the default is `false`), will add the resource parameter to token requests made for individual resources; in addition, it will provide list of the specified resources in the original authorization request.
>
>However, if you authorization system does not adopt Resource Indicators for OAuth 2.0, you may still be able to practice audience restriction by defining a resource (server) specific scope, as described in the [Audience Restricted Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-4.8.1.3) section of the OAuth 2.0 Security BCP. Thus, the openid-client-helper package implements the client portion of the Audience Restricted Access Tokens proposal, making the client ready to participate in an authorization system adopting this part of the BCP.

Finally, you may choose to overwrite some configuration defaults.

* `usePKCE`

  The authorization code grant is the recommended _authorization_ flow for all types of OAuth 2.0 clients interacting directly with the resource owner's user-agent. According to the OAuth 2.0 Security BCP, OAuth 2.0 clients [MUST use PKCE](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.1.1) extension to the authorization code grant and the authorization servers MUST support it. PKCE is lightweight, easy to implement, and allows both the client and the authorization server to verify the authorization code before it is exchanged for tokens. The default value for this setting is `true` and it is recommended to keep it that way.

  > If an authorization server does not support PKCE, providing extra parameters should not introduce any negative effects, for unrecognized query parameters MUST be ignored at the [authorization](https://tools.ietf.org/html/rfc6749#section-3.1) and the [token](https://tools.ietf.org/html/rfc6749#section-3.2) endpoints.

* `sessionKey`

  The helper aims to perform OAuth 2.0 authorization on behalf of a resource owner and to maintain the authorization state on the server side. In order to be able to identify authorization state specific to the resource owner, a helper instance needs access to the user session, which is presumably being managed by a framework. It is assumed that the session object is attached to the request and can be identified in the request handler by a key. This setting represents such a key and the setting's default value is `'session'`. If user session is not found, the helper instance will throw an error.

  > In lieu of a user session, a helper instance _could_ store the authorization state in a local variable and share it between users of the instance. Currently, this is not supported, because the primary audience for the library is thought to be a typical web application with unique user accounts.

* `authorizationId`

  The helper instance saves the authorization state under a key in the session object. By default, if no input is provided, the key is generated randomly based on the current timestamp. If `authorizationId` is defined, it's value is used to generate the key. Doing so allows different helper instances to share an authorization.

  > In order to scale an application horizontally, while using a shared session store, the key, under which the authorization state is stored, can be controlled, so that an authorization is available throughout instances of the application running in parallel. If `authorizationId` is not set, a random key is generated for each helper instance.
  
* `customize`

  You can customize the default behavior of the Issuer and Client classes and their respective instances as described in [Customizing](https://github.com/panva/node-openid-client/tree/master/docs#customizing) section of the openid-client documentation. For example:

  ```javascript
    customize: ({
      custom,
      Issuer,
      issuer,
      client
    }) => {
      if (Issuer) {
        // Something to do with the openid-client `Issuer` class.
      }
      if (issuer) {
        // Something to do with the openid-client `issuer` instance,
        // or the issuer.Client constructor.
      }
      if (client) {
        // Something to do with the openid-client `client` instance.
      }
    }
  ```

* `useResourceIndicators`

  If this parameter is assigned a `true` value, the openid-client-helper instance will include the list of the specified resources in the request made to the authorization endpoint and add the `resource` parameter to token requests made for individual resources, as described in [Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08#section-2). At the time of writing, the proposal is still a draft and may not be expected to be adopted universally. Hence, the default value for this setting is `false`.

  > Per [the original OAuth 2.0 spec](https://tools.ietf.org/html/rfc6749#section-3.1), request parameters sent to the authorization endpoint MUST NOT be included more than once. At the same time, the Resource Indicators for OAuth 2.0 draft calls for multiple `resource` parameters in the query string and allows for rejecting requests omitting this parameter. Thus, `useResourceIndicators` is introduced to accommodate particular implementations of the authorization server.

* `useMasterAccessToken`

  If it fails to obtain a valid access token for a resource, with this option set to `true`, the helper's `fetch` will proceed to the protected resource with the master access token. It is not a recommended way to make requests to a protected API, for it would discard the "audience restricted" paradigm. This setting was added for flexibility to account for possible special situations when no distinct resources can be identified. The default value for this setting is `false`.

All together:

```javascript
// Configuration object.
const openIdClientHelperParams = {
  issuerMetadata,
  clientMetadata,
  resources,
  // usePKCE: false, // The default is `true`.
  // sessionKey: 'some-unusual-session-identifier', // The default is 'session'.
  // useResourceIndicators: true, // The default is `false`
  // useMasterAccessToken: true, // The default is `false`.
  customize: ({
    custom,
    Issuer,
    issuer,
    client
  }) => {
    if (client) {
      // Allow two second skew between the Client and the Issuer.
      client[custom.clock_tolerance] = 2
    }
  } // The default is `undefined`
}

// New instance of openid-client-helper.
const {
  authorize,
  redirect,
  unauthorized,
  deauthorize,
  fetch,
  fetchMiddleware,
  getClient,
  getAuthorization,
  getClaims,
  getWWWAuthenticateHeaderAttributes
} = OpenIdClientHelper(openIdClientHelperParams)
```

> The full description of openid-client-helper configuration options can be found in the [API Reference](docs/README.md).

### <a id="how-to-make-it-work-new-authorization"></a>Authorize

[Back](#how-to-make-it-work)

In an Express.js environment the OAuth 2.0 authorization routes can utilize the `authorize` and the `redirect` middleware exposed by the openid-client-helper instance. By default, the middleware will derive its parameters from the instance configuration. Alternative and/or additional parameters can be provided as arguments. In its simplest implementation the routes may look like this:

```javascript
router.get('/authorize', authorize())

router.get('/redirect', redirect(), (req, res) => {
  res.redirect('/protected')
})
```

### <a id="how-to-make-it-work-existing-authorization"></a>Use Existing Authorization

[Back](#how-to-make-it-work)

The authorization state that an openid-client-helper instance maintains can be referenced by calling the public `getAuthorization({ req }) => authorization` method. The `req` parameter is there to provide the user session context, assuming the user session is being maintained. The `req` parameter is expected to be an object that has the session object as a property.

An active `authorization`, an authorization state object represented by an internal type, contains openid-client [TokenSet](https://github.com/panva/node-openid-client/tree/master/docs#tokenset) property as a top level member. This token set is to have an active refresh token that will be used for obtaining resource-specific access tokens. If the openid-client-helper Express.js middleware is used to authorize the client, this token set is populated automatically. Otherwise, a refresh token value can be copied in, or the whole token set object can be assigned a TokenSet that has been obtained by an external tool and has an active refresh token in it.

> Referencing a token set (instead of copying the refresh token value) may be beneficial if the authorization state needs to be shared between different parts of the client functionality. Otherwise, a separate, made by value, copy of the refresh token may become unexpectedly inactive due to [refresh token rotation](https://tools.ietf.org/html/rfc6749#section-10.4).

For example:

```javascript
const authorization = getAuthorization({
  req
})
.tokenSet = {
  refresh_token: someOtherAuthorization.refresh_token
}
```

Or:

```javascript
const authorization = getAuthorization({
  req
})
.tokenSet = someOtherAuthorization.tokenSet
```

### <a id="how-to-make-it-work-fetch-protected-resource"></a>Fetch

[Back](#how-to-make-it-work)

With the refresh token in place, the openid-client-helper public `fetch` method can be used to make requests to protected resources registered with the helper instance.

The underlying technology for the helper's fetch methods is the popular [node-fetch](https://www.npmjs.com/package/node-fetch) package. In addition to the original `fetch(url[, options])` arguments, the redefined helper's method takes an additional `req` parameter, which represents an object with the user session attached to it, so that user specific authorization state can be looked for. The fetch `Promise<Response>` is returned to the original caller. For example:

```javascript
const {
  // . . .
  fetch
} = OpenIdClientHelper(openIdClientHelperParams)

// An Express.js route accessing data at a protected endpoint.
router.get('/protected/resource', unauthorized({
  redirectTo: '/'
}), (req, res) => {
  fetch(
    'https://protected-resource-uri',
    undefined, // Use node-fetch default options for this request.
    req // Provide user session context.
  )
  .then((response) => {
    // Optionally, check if for some reason the resource-specific access token could not be renewed automatically.
    if (getWWWAuthenticateHeaderAttributes(response).error === 'invalid_token') {
      handleInvalidAccessToken() // For example, try to reauthorize the client.
    }

    // . . .
  }
}
```

> This means that even existing code utilizing node-fetch could be used with the redefined fetch method for making requests to a protected resource—by providing the additional `req` argument.

Note the use of another helper's public method, `getWWWAuthenticateHeaderAttributes(response) => object`. If the access token included in the request to a protected resource has expired, the response received from the resource server is to contain [WWW-Authenticate](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate) header with the error attribute populated with the "invalid_token" value, as described in the [OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750#section-3.1) standard. The helper itself checks for access token expiration using this method once and, if the token did expire, conveniently attempts to refresh it before repeating the fetch request. After that one attempt, it will pass the fetch response to the original caller unchecked. This means that if the access token deemed to be invalid by the original caller, it can go proactive and reauthorize the client, report the error to the user, terminate the application, etc.—whichever seems to be the most appropriate action in each particular situation.

Internally, the helper's fetch method calls another public method `fetchMiddleware(url, options, complete) => function (req, [res, next]) => Promise<Response> | next()`. As name suggests, this one can work as an Express.js middleware, but if it is only provided the `req` argument, a `Promise<Response>` is returned to the original caller.

> If, for some reason, `fetchMiddleware` is used directly, as a middleware, besides normal fetch arguments, `url` and `options`, it accepts a completion handler, so that the fetch response can be processed and, potentially, considered before the next middleware takes its turn.

### <a id="how-to-make-it-work-check-if-authorized"></a>Check If Authorized

[Back](#how-to-make-it-work)

The protected route in the aforementioned example uses `unauthorized({ redirectTo })` Express.js middleware included in the helper's public interface. The middleware simply checks for the presence of the top level `tokenSet` associated with the current authorization state and performs no further validation; if no `tokenSet` is found, it redirects to the specified in arguments route. This method is provided mainly as an example and can be replaced by a more sophisticated functionality utilizing the helper's `getAuthorization({ req }) => authorization` method.

### <a id="how-to-make-it-work-deauthorize"></a>Deauthorize

[Back](#how-to-make-it-work)

The `deauthorize({ complete })` middleware revokes all the tokens it can find in the current authorization state, attempts to perform [RP-Initiated Logout](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout), and destroys the authorization data. In addition, `deauthorize` creates `deauthorized` property in the authorization state and populates it with a set of messages and a set of errors, if any have been encountered during the deauthorization process.

RP-Initiated logout, when done via the front-channel, provides an opportunity for the user to interact with the OpenID provider's `end_session_endpoint`; for example, the user may be asked to confirm termination of their browser session. If the `end_session_endpoint` request contains `post_logout_redirect_uri` parameter, and the `post_logout_redirect_uri` value is registered for this relying party with the OpenID provider, the user will be redirected to that URI after the logout is complete. The openid-client-helper instance will attempt to construct an `end_session_endpoint` URI and redirect user to that location. If the `end_session_endpoint` URI cannot be constructed, the next middleware will be called.

If this behavior needs to be altered or aided, a completion handler can be provided in arguments for `deauthorize`. The completion handler can receive the middleware parameters and the `end_session_endpoint` as an additional argument: `complete({ req, res, next, endSessionUrl })`. In this case, the completion handler will be responsible for performing RP-Initiated logout, if one is desired, and can have it done either via the front-channel or the back-channel. Then, the completion handler can follow up with any necessary redirection.

## <a id="examples"></a>Examples

[Back to top](#top)

### [Basic Express.js example](examples/express/README.md)
### [ForgeRock example](https://github.com/ForgeRock/exampleOAuth2Clients/tree/master/node-openid-client)