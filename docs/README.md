<a name="module_openid-client-helper"></a>

## openid-client-helper
The main module.


* [openid-client-helper](#module_openid-client-helper)
    * [module.exports(param0)](#exp_module_openid-client-helper--module.exports) ⇒ <code>object</code> ⏏
        * _instance_
            * [.authorize([options])](#module_openid-client-helper--module.exports+authorize)
            * [.redirect([param0])](#module_openid-client-helper--module.exports+redirect)
            * [.deauthorize([param0])](#module_openid-client-helper--module.exports+deauthorize)
            * [.unauthorized([param0])](#module_openid-client-helper--module.exports+unauthorized) ⇒ <code>function</code>
            * [.fetch(url, [options], [req])](#module_openid-client-helper--module.exports+fetch) ⇒ <code>Promise.&lt;Response&gt;</code>
            * [.fetchMiddleware(url, [options], [complete])](#module_openid-client-helper--module.exports+fetchMiddleware) ⇒ <code>function</code>
            * [.refreshResourceToken([param0])](#module_openid-client-helper--module.exports+refreshResourceToken) ⇒ <code>Promise.&lt;object&gt;</code>
            * [.getIssuer()](#module_openid-client-helper--module.exports+getIssuer) ⇒ <code>Promise.&lt;object&gt;</code>
            * [.getClient()](#module_openid-client-helper--module.exports+getClient) ⇒ <code>Promise.&lt;object&gt;</code>
            * [.getAuthorization([param0])](#module_openid-client-helper--module.exports+getAuthorization) ⇒ <code>authorization</code>
            * [.deleteAuthorization([param0])](#module_openid-client-helper--module.exports+deleteAuthorization)
            * [.getClaims(param0)](#module_openid-client-helper--module.exports+getClaims) ⇒ <code>object</code>
            * [.getWWWAuthenticateHeaderAttributes(response)](#module_openid-client-helper--module.exports+getWWWAuthenticateHeaderAttributes) ⇒ <code>object</code>
        * _inner_
            * [~authorizationKey](#module_openid-client-helper--module.exports..authorizationKey)
            * [~authorization](#module_openid-client-helper--module.exports..authorization) : <code>object</code>

<a name="exp_module_openid-client-helper--module.exports"></a>

### module.exports(param0) ⇒ <code>object</code> ⏏
Represents an `openid-client-helper` instance.

**Kind**: Exported function  
**Returns**: <code>object</code> - An instance of `openid-client-helper`.  
**See**: [openid-client documentation](https://github.com/panva/node-openid-client/tree/master/docs) for details on use of `Issuer`, `Client`, `TokenSet`, and `generators` imported from the openid-client library.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| param0 | <code>object</code> |  | Object wrapping all the arguments passed to the Constructor. |
| param0.issuerMetadata | <code>object</code> |  | OpenID Provider (OP) metadata |
| param0.issuerMetadata.issuer | <code>string</code> |  | The OP's Configuration Information endpoint or `openid-client` `Issuer` identifier |
| [...param0.issuerMetadata] | <code>\*</code> |  | Additional `Issuer` metadata items. |
| param0.clientMetadata | <code>object</code> |  | `openid-client` `Client` metadata. |
| param0.clientMetadata.client_id | <code>string</code> |  | The OAuth 2.0 client identifier, as described in [The OAuth 2.0 Authorization Framework, section-2.2](https://tools.ietf.org/html/rfc6749#section-2.2). |
| param0.clientMetadata.client_secret | <code>string</code> |  | The OAuth 2.0 client password, as described in [The OAuth 2.0 Authorization Framework, section-2.3.1](https://tools.ietf.org/html/rfc6749#section-2.3.1). |
| param0.clientMetadata.token_endpoint_auth_method | <code>string</code> |  | The OAuth 2.0 client authentication method, as described in [OAuth 2.0 Dynamic Client Registration Protocol, section-2](https://tools.ietf.org/html/rfc7591#section-2). |
| [param0.clientMetadata.redirect_uri] | <code>string</code> |  | The OAuth 2.0 redirect_uri to use in this `openid-client-helper` instance authorization request, as described in [The OAuth 2.0 Authorization Framework, section-4.1.1](https://tools.ietf.org/html/rfc6749#section-4.1.1). Required and has to be registered with the authorization server, if the instance is used to perform authorization via the front-channel. |
| [param0.clientMetadata.post_logout_redirect_uri] | <code>string</code> |  | The OpenID Connect Relying Party (RP) post-logout redirect URI, to use in this `openid-client-helper` instance after the RP-Initiated Logout, as described in [OpenID Connect Session Management 1.0, Redirection to RP After Logout](https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout). Currently, `openid-client` does not accept a single valued `post_logout_redirect_uri` parameter, but `openid-client-helper` does. |
| [...param0.clientMetadata] | <code>\*</code> |  | Additional `Client` metadata items, as described in [openid-client docs](https://github.com/panva/node-openid-client/tree/master/docs#new-clientmetadata-jwks). |
| [param0.usePKCE] | <code>boolean</code> | <code>true</code> | Indicates whether or not to use [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636) (PKCE). |
| [param0.resources] | <code>object</code> | <code>{ &#x27;https://&#x27;: { scope: &#x27;*&#x27; } }</code> | A set of resources associated with resource specific scope(s). Each resource key is, generally, to comply with the proposed [Resource Parameter](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08#section-2) definition, as it may be used as the resource indicator in systems that adopt the draft. The resource keys will be compared against the URI in requests to a protected API resource, and the key matching the left part of the URI the most will be used to retrieve corresponding access token. |
| [param0.useMasterAccessToken] | <code>boolean</code> | <code>false</code> | Indicates whether or not the "master" access token, the one associated with scopes approved by the resource owner, is to be used if a resource specific access token cannot be obtained. Setting this to `true` is not normally recommended, for it leads to use of an access token that is not audience restricted. |
| [param0.sessionKey] | <code>string</code> | <code>&quot;session&quot;</code> | The key identifying the session object attached to requests. |
| [param0.authorizationId] | <code>string</code> | | Identifier for the authorization state saved in the session object, so that an authorization could be shared between the helper instances and used for horizontal scaling. |
| [param0.useResourceIndicators] | <code>boolean</code> | <code>false</code> | Indicates whether [Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08) are supported by the authorization server. |
| [param0.customize] | <code>function</code> |  | A function to modify openid-client defaults using its [Customizing](https://github.com/panva/node-openid-client/tree/master/docs#customizing) means. The function will be sent the `custom` options object and the `Issuer` constructor. When an `issuer` or `client` instance is created, it will be provided as a parameter along with the `custom` object. This means that the `customize` function should check for presence of the `Issuer`, `issuer`, or/and `client` parameters, if those were to be modified. |

<a name="module_openid-client-helper--module.exports+authorize"></a>

#### module.exports.authorize([options])
Middleware.
Constructs an authorization URL and redirects to the issuer's authorization endpoint.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  

| Param | Type | Description |
| --- | --- | --- |
| [options] | <code>object</code> | Authorization parameters to be explicitly included in the authorization request; these will overwrite parameters derived from the module configuration. |

<a name="module_openid-client-helper--module.exports+redirect"></a>

#### module.exports.redirect([param0])
Middleware.
Captures redirection parameters and performs access token request.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{}</code> | Redirection parameters to be explicitly included in the access token request; these will overwrite parameters normally derived from the existing authorization state. |
| [param0.redirect_uri] | <code>string</code> |  | `redirect_uri` used in the authorization request. |
| [param0.parameters] | <code>object</code> | <code>{}</code> | Parameters expected in the authorization response. |
| [param0.checks] | <code>object</code> | <code>{}</code> | Verifiers present in the authorization response or to be included in access token request. |
| [param0.extras] | <code>object</code> | <code>{}</code> | Extra parameters to be included in the access token request. |

<a name="module_openid-client-helper--module.exports+deauthorize"></a>

#### module.exports.deauthorize([param0])
Middleware.
Revokes tokens, destroys the current authorization state,
and performs RP initiated logout or calls a completion handler if one is provided.
Attaches messages and errors, encountered during deauthorization, to the authorization state.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{}</code> | The options object. |
| [param0.complete] | <code>function</code> |  | An optional completion handler (function) to be called after the authorization state has been altered. |

<a name="module_openid-client-helper--module.exports+unauthorized"></a>

#### module.exports.unauthorized([param0]) ⇒ <code>function</code>
Middleware.
Checks for valid authorization.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>function</code> - Checks for presence of a token set in the authorization state.
If there is no token set, redirects to the provided route; otherwise, calls the next middleware.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{}</code> | The options object. |
| [param0.redirectTo] | <code>string</code> | <code>&quot;&#x27;/&#x27;&quot;</code> | Path to redirect unauthorized users to. |

<a name="module_openid-client-helper--module.exports+fetch"></a>

#### module.exports.fetch(url, [options], [req]) ⇒ <code>Promise.&lt;Response&gt;</code>
Calls [module:openid-client-helper#fetchMiddleware] with the passed in URI and options.
Then calls the returned function with the `req` object as the single argument
to provide the user session context.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>Promise.&lt;Response&gt;</code> - Promise resolving to an HTTP response.  
**See**: [node-fetch README](https://www.npmjs.com/package/node-fetch)  

| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The resource URI to make the request to. |
| [options] | <code>object</code> | Options for the HTTP request. |
| [req] | <code>object</code> | The `req` object used to identify the authorization state. |

<a name="module_openid-client-helper--module.exports+fetchMiddleware"></a>

#### module.exports.fetchMiddleware(url, [options], [complete]) ⇒ <code>function</code>
Performs node-fetch request to a protected endpoint.
Crafts a node-fetch HTTP request with an access token for the protected resource.
If the resource is not found, or the access token cannot be obtained,
the fetch request is performed without adding Authorization header to the request options.
If the resource is found, the access token associated with it is used.
If the access token is reported as invalid via the HTTP WWW-Authenticate response header,
one attempt to refresh the access token is performed and the request is repeated.
While this method can be used as a middleware constructor,
normally it would accept a call from the `fetch` one and return a fetch `Promise`.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>function</code> - A function that performs a node-fetch request.
If `res` and `next` are provided in `arguments`, the function optionally handles the fetch results and calls the next middleware.
Otherwise, it returns `Promise` that resolves to the fetch results.  
**See**: [node-fetch README](https://www.npmjs.com/package/node-fetch)  

| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The resource URI to make the request to. |
| [options] | <code>object</code> | Options for the HTTP request. |
| [complete] | <code>function</code> | A completion handler to call if used as a middleware. For example, the completion handler can store fetch results in an accessible location before calling the next middleware. |

<a name="module_openid-client-helper--module.exports+refreshResourceToken"></a>

#### module.exports.refreshResourceToken([param0]) ⇒ <code>Promise.&lt;object&gt;</code>
Refreshes access token for a resource.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>Promise.&lt;object&gt;</code> - A Promise resolving to a token set for the specified resource.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{}</code> | The options object. |
| [param0.req] | <code>object</code> |  | The `req` object. |
| [param0.resourceKey] | <code>string</code> |  | A resource identifier; normally, the left part of a REST endpoint or a full URI. |

<a name="module_openid-client-helper--module.exports+getIssuer"></a>

#### module.exports.getIssuer() ⇒ <code>Promise.&lt;object&gt;</code>
Returns an instance of `openid-client` `Issuer` created with the metadata passed in the module constructor.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Promise resolving to an `openid-client` `Issuer` instance.  
<a name="module_openid-client-helper--module.exports+getClient"></a>

#### module.exports.getClient() ⇒ <code>Promise.&lt;object&gt;</code>
Returns an instance of `openid-client` `Client` created with the metadata passed in the module constructor.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Promise resolving to an `openid-client` `Client` instance.  
<a name="module_openid-client-helper--module.exports+getAuthorization"></a>

#### module.exports.getAuthorization([param0]) ⇒ <code>authorization</code>
Obtains authorization state identified by a key and associated with the user session.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>authorization</code> - The authorization state associated with this instance of openid-client-helper.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{req: {}}</code> | The options object. |
| [param0.req] | <code>object</code> | <code>{}</code> | The `req` object. |

<a name="module_openid-client-helper--module.exports+deleteAuthorization"></a>

#### module.exports.deleteAuthorization([param0])
Removes authorization state identified by a key and associated with the user session.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [param0] | <code>object</code> | <code>{req: {}}</code> | The options object. |
| [param0.req] | <code>object</code> | <code>{}</code> | The `req` object. |

<a name="module_openid-client-helper--module.exports+getClaims"></a>

#### module.exports.getClaims(param0) ⇒ <code>object</code>
Obtains parsed id_token claims from a `TokenSet` data.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  

| Param | Type |
| --- | --- |
| param0 | <code>object</code> | 
| param0.tokenSet | <code>object</code> | 

<a name="module_openid-client-helper--module.exports+getWWWAuthenticateHeaderAttributes"></a>

#### module.exports.getWWWAuthenticateHeaderAttributes(response) ⇒ <code>object</code>
Returns attributes of the WWW-Authenticate response header from an HTTP response object.

**Kind**: instance method of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Returns**: <code>object</code> - Attributes found in the header.  

| Param | Type | Description |
| --- | --- | --- |
| response | <code>object</code> | An HTTP response to derive WWW-Authenticate header from. |

<a name="module_openid-client-helper--module.exports..authorizationKey"></a>

#### module.exports~authorizationKey
Unique identifier for this authorization in session.

**Kind**: inner constant of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
<a name="module_openid-client-helper--module.exports..authorization"></a>

#### module.exports~authorization : <code>object</code>
**Kind**: inner typedef of [<code>module.exports</code>](#exp_module_openid-client-helper--module.exports)  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| tokenSet | <code>TokenSet</code> | An openid-client TokenSet object. |
| resources | <code>object</code> | Set of resources protected by OAuth 2.0. |
| resources.resource | <code>object</code> | Individual resource. |
| resources.resource.tokenSet | <code>TokenSet</code> | An openid-client TokenSet object that is specific to individual resource. |
| deauthorized | <code>object</code> | A container for messages and errors encountered during deauthorization. |
| deauthorized.messages | <code>object</code> |  |
| deauthorized.errors | <code>object</code> |  |

