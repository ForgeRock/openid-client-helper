/**
 * The main module.
 * @module openid-client-helper
 */

'use strict'

const crypto = require('crypto')
const {
  Issuer,
  generators,
  TokenSet,
  custom
} = require('openid-client')
const fetch = require('node-fetch')
const {
  assignJSON,
  getProperty,
  setProperty
} = require('./utilities')

/**
 * Represents an `openid-client-helper` instance.
 * @param {object} param0 Object wrapping all the arguments passed to the Constructor.
 * @param {object} param0.issuerMetadata OpenID Provider (OP) metadata
 * @param {string} param0.issuerMetadata.issuer The OP's Configuration Information endpoint
 * or `openid-client` `Issuer` identifier
 * @param {...*} [param0.issuerMetadata=undefined] Additional `Issuer` metadata items.
 * @param {object} param0.clientMetadata `openid-client` `Client` metadata.
 * @param {string} param0.clientMetadata.client_id The OAuth 2.0 client identifier,
 * as described in [The OAuth 2.0 Authorization Framework, section-2.2]{@link https://tools.ietf.org/html/rfc6749#section-2.2}.
 * @param {string} param0.clientMetadata.client_secret The OAuth 2.0 client password,
 * as described in [The OAuth 2.0 Authorization Framework, section-2.3.1]{@link https://tools.ietf.org/html/rfc6749#section-2.3.1}.
 * @param {string} param0.clientMetadata.token_endpoint_auth_method The OAuth 2.0 client authentication method,
 * as described in [OAuth 2.0 Dynamic Client Registration Protocol, section-2]{@link https://tools.ietf.org/html/rfc7591#section-2}.
 * @param {string} [param0.clientMetadata.redirect_uri=undefined] The OAuth 2.0 redirect_uri to use in this `openid-client-helper` instance authorization request,
 * as described in [The OAuth 2.0 Authorization Framework, section-4.1.1]{@link https://tools.ietf.org/html/rfc6749#section-4.1.1}.
 * Required and has to be registered with the authorization server, if the instance is used to perform authorization via the front-channel.
 * @param {string} [param0.clientMetadata.post_logout_redirect_uri=undefined] The OpenID Connect Relying Party (RP) post-logout redirect URI,
 * to use in this `openid-client-helper` instance after the RP-Initiated Logout,
 * as described in [OpenID Connect Session Management 1.0, Redirection to RP After Logout]{@link https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout}.
 * Currently, `openid-client` does not accept a single valued `post_logout_redirect_uri` parameter, but `openid-client-helper` does.
 * @param {...*} [param0.clientMetadata=undefined] Additional `Client` metadata items,
 * as described in [openid-client docs]{@link https://github.com/panva/node-openid-client/tree/master/docs#new-clientmetadata-jwks}.
 * @param {boolean} [param0.usePKCE=true] Indicates whether or not to use [Proof Key for Code Exchange]{@link https://tools.ietf.org/html/rfc7636} (PKCE).
 * @param {object} [param0.resources={ 'https://': { scope: '*' } }] A set of resources associated with resource specific scope(s).
 * Each resource key is, generally, to comply with the proposed [Resource Parameter](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08#section-2) definition,
 * as it may be used as the resource indicator in systems that adopt the draft.
 * The resource keys will be compared against the URI in requests to a protected API resource,
 * and the key matching the left part of the URI the most will be used to retrieve corresponding access token.
 * @param {boolean} [param0.useMasterAccessToken=false] Indicates whether or not the "master" access token,
 * the one associated with scopes approved by the resource owner,
 * is to be used if a resource specific access token cannot be obtained.
 * Setting this to `true` is not normally recommended,
 * for it leads to use of an access token that is not audience restricted.
 * @param {string} [param0.sessionKey=session] The key identifying the session object attached to requests.
 * @param {string} [param0.authorizationId] Identifier for the authorization state saved in the session object, so that an authorization could be shared between the helper instances and used for horizontal scaling.
 * @param {boolean} [param0.useResourceIndicators=false] Indicates whether [Resource Indicators for OAuth 2.0]{@link https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08}
 * are supported by the authorization server.
 * @param {function} [param0.customize] A function to modify openid-client defaults using its [Customizing]{@link https://github.com/panva/node-openid-client/tree/master/docs#customizing} means.
 * The function will be sent the `custom` options object and the `Issuer` constructor.
 * When an `issuer` or `client` instance is created, it will be provided as a parameter along with the `custom` object.
 * This means that the `customize` function should check for presence of the `Issuer`, `issuer`, or/and `client` parameters,
 * if those were to be modified.
 * @returns {object} An instance of `openid-client-helper`.
 * @see [openid-client documentation]{@link https://github.com/panva/node-openid-client/tree/master/docs} for details on use of `Issuer`, `Client`, `TokenSet`, and `generators` imported from the openid-client library.
*/
module.exports = function ({
  issuerMetadata,
  clientMetadata,
  usePKCE = true,
  resources = {
    'https://': {
      scope: '*'
    }
  },
  useMasterAccessToken = false,
  sessionKey = 'session',
  authorizationId,
  useResourceIndicators = false,
  customize
}) {
  if (typeof customize === 'function') {
    customize({
      custom,
      Issuer
    })
  }

  /**
   * @typedef authorization
   * @type {object}
   * @property {TokenSet} tokenSet An openid-client TokenSet object.
   * @property {object} resources Set of resources protected by OAuth 2.0.
   * @property {object} resources.resource Individual resource.
   * @property {TokenSet} resources.resource.tokenSet An openid-client TokenSet object
   * that is specific to individual resource.
   * @property {object} deauthorized A container for messages and errors encountered during deauthorization.
   * @property {object} deauthorized.messages
   * @property {object} deauthorized.errors
   */

  // /**
  //  * Serves as an alternative, shared storage for authorizations, if the user session cannot be found.
  //  */
  // const local = {}

  const hashes = crypto.getHashes()
  /**
   *  Identifier for this authorization in session. Base on custom data or generate randomly.
   */
  const authorizationKey = crypto.createHash(
    hashes
    .reverse()
    .find((hash) => {
      return hash.match(/^sha1$|^sha256$/)
    }) || hashes[hashes.length - 1]
  )
  .update(authorizationId || (new Date()).valueOf().toString())
  .digest('base64')

  const helper = {
    /**
     * Middleware.
     * Constructs an authorization URL and redirects to the issuer's authorization endpoint.
     * @param {object} [options] Authorization parameters to be explicitly included in the authorization request;
     * these will overwrite parameters derived from the module configuration.
     * @alias module:openid-client-helper#authorize
     */
    authorize: (options) => {
      return (req, res, next) => {
        return helper.getClient()
        .then((client) => {
          const authorization = helper.getAuthorization({
            req
          })
          authorization.inProgress = true
          authorization.params = {}

          authorization.params.state = generators.state()

          if (client.redirect_uris && client.redirect_uris.length) {
            authorization.params.redirect_uri = client.redirect_uris[0]
          }
          if (client.response_types && client.response_types.length) {
            authorization.params.response_type = client.response_types[0]
          }
          if (usePKCE) {
            authorization.code_verifier = generators.codeVerifier()
          }
          if (authorization.code_verifier) {
            authorization.params.code_challenge = generators.codeChallenge(authorization.code_verifier)
            authorization.params.code_challenge_method = 'S256'
          }
          authorization.params.nonce = generators.nonce()

          assignJSON(authorization.params, options)

          if (!authorization.params.scope) {
            let scope = []

            scope.push('openid')

            scope = scope.concat(Object.keys(resources).map((resource) => {
              return resources[resource].scope.split(' ')
            })
            .reduce((result, value) => {
              return result.concat(value)
            }, [])
            .filter((scope) => {
              return scope.trim()
            }))

            scope = [...new Set(scope)]

            if (scope.length) {
              authorization.params.scope = scope.join(' ')
            }
          }

          if (useResourceIndicators) {
            authorization.params.resource = Object.keys(resources)
          }

          res.redirect(client.authorizationUrl(authorization.params))
        })
        .catch((e) => {
          next(e)
        })
      }
    },
    /**
     * Middleware.
     * Captures redirection parameters and performs access token request.
     * @param {object} [param0={}] Redirection parameters to be explicitly included in the access token request;
     * these will overwrite parameters normally derived from the existing authorization state.
     * @param {string} [param0.redirect_uri] `redirect_uri` used in the authorization request.
     * @param {object} [param0.parameters={}] Parameters expected in the authorization response.
     * @param {object} [param0.checks={}] Verifiers present in the authorization response
     * or to be included in access token request.
     * @param {object} [param0.extras={}] Extra parameters to be included in the access token request.
     * @alias module:openid-client-helper#redirect
     */
    redirect: ({
      // eslint-disable-next-line camelcase
      redirect_uri,
      parameters = {},
      checks = {},
      extras = {}
    } = {}) => {
      return (req, res, next) => {
        const authorization = helper.getAuthorization({
          req
        })

        return helper.getClient()
        .then((client) => {
          const callbackParams = []

          // Capture parameters provided to the middleware.
          const redirectParams = assignJSON({}, {
            redirect_uri,
            parameters,
            checks,
            extras
          })

          // Capture parameters from existing authorization request.
          const authorizationParams = assignJSON({}, {
            redirect_uri: authorization.params.redirect_uri,
            parameters: client.callbackParams(req),
            checks: {
              code_verifier: authorization.code_verifier,
              state: authorization.params.state,
              nonce: authorization.params.nonce
            }
          })

          // Combine the middleware and the authorization parameters, giving preference to the former.
          Object.assign(redirectParams, authorizationParams)

          // Combine arguments for `openid-client` `client.callback()`
          callbackParams.push(redirectParams.redirect_uri)
          if (Object.keys(redirectParams.parameters).length) {
            callbackParams.push(redirectParams.parameters)
          } else {
            callbackParams.push(undefined)
          }
          if (Object.keys(redirectParams.checks).length) {
            callbackParams.push(redirectParams.checks)
          } else {
            callbackParams.push(undefined)
          }
          if (Object.keys(redirectParams.extras).length) {
            callbackParams.push(extras)
          }

          // Make call to the token endpoint.
          return client.callback(
            ...callbackParams
          )
          .then((tokenSet) => {
            // Save the token set in the current authorization state.
            authorization.inProgress = false

            authorization.deauthorized = undefined

            authorization.tokenSet = tokenSet

            next()
          })
          .catch((e) => {
            throw e
          })
        })
        .catch((e) => {
          authorization.inProgress = false

          next(e)
        })
      }
    },
    /**
     * Middleware.
     * Revokes tokens, destroys the current authorization state,
     * and performs RP initiated logout or calls a completion handler if one is provided.
     * Attaches messages and errors, encountered during deauthorization, to the authorization state.
     * @param {object} [param0={}] The options object.
     * @param {function} [param0.complete] An optional completion handler (function)
     * to be called after the authorization state has been altered.
     * @alias module:openid-client-helper#deauthorize
     */
    deauthorize: ({
      complete
    } = {}) => {
      return (req, res, next) => {
        return helper.getClient()
        .then((client) => {
          const authorization = helper.getAuthorization({
            req
          })
          const messages = {}
          const errors = {}
          const promises = []

          var endSessionUrl

          const endSessionUrlParams = {}
          if ((authorization.tokenSet || {}).id_token) {
            endSessionUrlParams.id_token_hint = authorization.tokenSet.id_token
          }

          const postLogoutRedirectUris = client.post_logout_redirect_uris || []
          if (client.post_logout_redirect_uri) {
            postLogoutRedirectUris.unshift(client.post_logout_redirect_uri)
          }
          if (postLogoutRedirectUris && postLogoutRedirectUris.length) {
            endSessionUrlParams.post_logout_redirect_uri = postLogoutRedirectUris[0]
          }

          try {
            endSessionUrl = client.endSessionUrl(endSessionUrlParams)
          } catch (e) {
            errors.end_session_url = e
          }

          const accessToken = (authorization.tokenSet || {}).access_token
          const refreshToken = (authorization.tokenSet || {}).refresh_token

          if (accessToken) {
            promises.push(
              client.revoke(accessToken, 'access_token')
              .then(() => {
                messages[accessToken] = {
                  message: 'Revoked master access token'
                }
              })
              .catch((e) => {
                errors[accessToken] = e
              })
            )
          }

          Object.keys(authorization.resources).forEach((resourceKey) => {
            const resource = authorization.resources[resourceKey]
            const accessToken = getProperty(resource, 'tokenSet.access_token')
            if (accessToken) {
              promises.push(
                client.revoke(accessToken, 'access_token')
                .then(() => {
                  messages[accessToken] = { message: `Revoked access token for ${resourceKey}` }
                })
                .catch((e) => {
                  errors[accessToken] = e
                })
              )
            }
          })

          if (refreshToken) {
            promises.push(
              client.revoke(refreshToken, 'refresh_token')
              .then(() => {
                messages[refreshToken] = { message: 'Revoked refresh token' }
              })
              .catch((e) => {
                errors[refreshToken] = e
              })
            )
          }

          Promise.all(promises)
          .finally(() => {
            helper.deleteAuthorization({
              req
            })

            const authorization = helper.getAuthorization({
              req
            })

            authorization.deauthorized = {
              messages,
              errors
            }

            if (typeof complete === 'function') {
              complete({
                req,
                res,
                next,
                endSessionUrl
              })

              return
            }

            if (endSessionUrl) {
              res.redirect(endSessionUrl)
            } else {
              next()
            }
          })
        })
        .catch((e) => {
          next(e)
        })
      }
    },
    /**
     * Middleware.
     * Checks for valid authorization.
     * @param {object} [param0={}] The options object.
     * @param {string} [param0.redirectTo='/'] Path to redirect unauthorized users to.
     * @returns {function} Checks for presence of a token set in the authorization state.
     * If there is no token set, redirects to the provided route; otherwise, calls the next middleware.
     * @alias module:openid-client-helper#unauthorized
     */
    unauthorized: ({
      redirectTo = '/'
    }) => {
      return (req, res, next) => {
        const authorization = helper.getAuthorization({
          req
        })

        if (authorization.tokenSet) {
          next()
        } else {
          res.redirect(redirectTo)
        }
      }
    },
    /**
     * Calls [module:openid-client-helper#fetchMiddleware] with the passed in URI and options.
     * Then calls the returned function with the `req` object as the single argument
     * to provide the user session context.
     * @param {string} url The resource URI to make the request to.
     * @param {object} [options] Options for the HTTP request.
     * @param {object} [req] The `req` object used to identify the authorization state.
     * @returns {Promise<Response>} Promise resolving to an HTTP response.
     * @alias module:openid-client-helper#fetch
     * @see [node-fetch README]{@link https://www.npmjs.com/package/node-fetch}
     */
    fetch: (
      url,
      options,
      req
    ) => {
      return helper.fetchMiddleware(url, options)(req)
    },
    /**
     * Performs node-fetch request to a protected endpoint.
     * Crafts a node-fetch HTTP request with an access token for the protected resource.
     * If the resource is not found, or the access token cannot be obtained,
     * the fetch request is performed without adding Authorization header to the request options.
     * If the resource is found, the access token associated with it is used.
     * If the access token is reported as invalid via the HTTP WWW-Authenticate response header,
     * one attempt to refresh the access token is performed and the request is repeated.
     * While this method can be used as a middleware constructor,
     * normally it would accept a call from the `fetch` one and return a fetch `Promise`.
     * @param {string} url The resource URI to make the request to.
     * @param {object} [options] Options for the HTTP request.
     * @param {function} [complete] A completion handler to call if used as a middleware.
     * For example, the completion handler can store fetch results in an accessible location before calling the next middleware.
     * @returns {function} A function that performs a node-fetch request.
     * If `res` and `next` are provided in `arguments`, the function optionally handles the fetch results and calls the next middleware.
     * Otherwise, it returns `Promise` that resolves to the fetch results.
     * @alias module:openid-client-helper#fetchMiddleware
     * @see [node-fetch README]{@link https://www.npmjs.com/package/node-fetch}
     */
    fetchMiddleware: (
      url,
      options,
      complete
    ) => {
      return (req, res, next) => {
        function success (response) {
          if (!(res && next)) {
            return response
          } else {
            // If used as a middleware, and the completion handler is provided, process response.
            if (typeof complete === 'function') {
              complete({
                req,
                res,
                next,
                response
              })

              return
            }

            next()
          }
        }

        function failure (e) {
          if (!next) {
            throw e
          } else {
            // If used as a middleware, and the completion handler is provided, process response.
            if (typeof complete === 'function') {
              complete({
                req,
                res,
                next,
                error: e
              })

              return
            }

            next(e)
          }
        }

        function refreshAndFetch () {
          return helper.refreshResourceToken({
            req,
            resourceKey
          })
          .then((tokenSet) => {
            const fetchOptions = {}
            Object.assign(fetchOptions, options)

            if ((tokenSet || {}).access_token) {
              setProperty(fetchOptions, 'headers.Authorization', `Bearer ${tokenSet.access_token}`)
            }

            return fetch(url, fetchOptions)
          })
          .catch((e) => {
            throw e
          })
        }

        const authorization = helper.getAuthorization({
          req
        })

        const resourceKey = Object.keys(authorization.resources || {}).filter((resourceKey) => {
          return url.indexOf(resourceKey) === 0
        }).sort((a, b) => {
          return b.length - a.length
        })[0]

        return refreshAndFetch()
        .then((response) => {
          // Attempt to refresh an expired access token.
          if (helper.getWWWAuthenticateHeaderAttributes(response).error === 'invalid_token') {
            authorization.resources[resourceKey].tokenSet = undefined

            return refreshAndFetch()
            .then((response) => {
              return success(response)
            })
            .catch((e) => {
              throw e
            })
          } else {
            return success(response)
          }
        })
        .catch((e) => {
          failure(e)
        })
      }
    },
    /**
     * Refreshes access token for a resource.
     * @param {object} [param0={}] The options object.
     * @param {object} [param0.req] The `req` object.
     * @param {string} [param0.resourceKey] A resource identifier; normally, the left part of a REST endpoint or a full URI.
     * @returns {Promise<object>} A Promise resolving to a token set for the specified resource.
     * @alias module:openid-client-helper#refreshResourceToken
     */
    refreshResourceToken: ({
      req,
      resourceKey
    } = {}) => {
      function doClientRefresh () {
        return helper.getClient()
        .then((client) => {
          const params = []
          params.push(authorization.tokenSet.refresh_token)

          // The "resource" parameter, as described in https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08#section-2.2
          const extras = {
          }

          if (authorization.resources[resourceKey].scope) {
            setProperty(extras, 'exchangeBody.scope', authorization.resources[resourceKey].scope)
          }

          if (useResourceIndicators) {
            setProperty(extras, 'exchangeBody.resource', resourceKey)
          }

          if (Object.keys(extras).length) {
            params.push(extras)
          }

          return client.refresh(
            ...params
          )
        })
        .catch((e) => {
          throw e
        })
      }

      const authorization = helper.getAuthorization({
        req
      })

      if (!(authorization.resources && authorization.resources[resourceKey])) {
        // Resource not found.
        return Promise.resolve()
      }

      return new Promise((resolve, reject) => {
        if (!authorization.resources[resourceKey].tokenSet) {
          doClientRefresh()
          .then((tokenSet) => {
            if (tokenSet.refresh_token) {
              authorization.tokenSet.refresh_token = tokenSet.refresh_token
            }

            setProperty(authorization.resources[resourceKey], 'tokenSet.access_token', tokenSet.access_token)
            if (tokenSet.id_token) {
              setProperty(authorization.resources[resourceKey], 'tokenSet.id_token', tokenSet.id_token)
            }
          })
          .catch((e) => {
            authorization.refreshed = {
              errors: [
                e
              ]
            }

            setProperty(authorization.resources[resourceKey], 'tokenSet.access_token', undefined)

            if (useMasterAccessToken) {
              setProperty(authorization.resources[resourceKey], 'tokenSet.access_token', authorization.tokenSet.access_token)
            }
          })
          .finally(() => {
            resolve(authorization.resources[resourceKey].tokenSet)
          })
        } else {
          resolve(authorization.resources[resourceKey].tokenSet)
        }
      })
    },
    /**
     * Returns an instance of `openid-client` `Issuer` created with the metadata passed in the module constructor.
     * @returns {Promise<object>} Promise resolving to an `openid-client` `Issuer` instance.
     * @alias module:openid-client-helper#getIssuer
     */
    getIssuer: () => {
      return Issuer.discover(issuerMetadata.issuer)
      .then((issuer) => {
        if (typeof customize === 'function') {
          customize({
            custom,
            issuer
          })
        }

        Object.keys(issuerMetadata).forEach((key) => {
          if (!issuer[key]) {
            Object.defineProperty(issuer, key, {
              value: issuerMetadata[key],
              writable: false
            })
          }
        })

        return issuer
      })
      .catch((e) => {
        const issuer = new Issuer(issuerMetadata)

        if (typeof customize === 'function') {
          customize({
            custom,
            issuer
          })
        }

        return issuer
      })
      .catch((e) => {
        throw e
      })
    },
    /**
     * Returns an instance of `openid-client` `Client` created with the metadata passed in the module constructor.
     * @returns {Promise<object>} Promise resolving to an `openid-client` `Client` instance.
     * @alias module:openid-client-helper#getClient
     */
    getClient: () => {
      return helper.getIssuer()
      .then((issuer) => {
        const client = new issuer.Client(clientMetadata)

        if (typeof customize === 'function') {
          customize({
            custom,
            client
          })
        }

        return client
      })
      .catch((e) => {
        throw e
      })
    },
    /**
     * Obtains authorization state identified by a key and associated with the user session.
     * @param {object} [param0={req: {}}] The options object.
     * @param {object} [param0.req={}] The `req` object.
     * @returns {authorization} The authorization state associated with this instance of openid-client-helper.
     * @alias module:openid-client-helper#getAuthorization
     */
    getAuthorization: ({
      req = {}
    } = {
      req: {}
    }) => {
      const session = req[sessionKey] // Require user session. || local

      if (!session) {
        throw new Error('User session is not found.')
      }

      const authorization = session[authorizationKey] = session[authorizationKey] || {}

      // Save list of protected by OAuth 2.0 resources in the current authorization state.
      authorization.resources = authorization.resources || assignJSON({}, resources)

      return authorization
    },
    /**
     * Removes authorization state identified by a key and associated with the user session.
     * @param {object} [param0={req: {}}] The options object.
     * @param {object} [param0.req={}] The `req` object.
     * @alias module:openid-client-helper#deleteAuthorization
     */
    deleteAuthorization: ({
      req = {}
    } = {
      req: {}
    }) => {
      const session = req[sessionKey] // Require user session. || local

      if (!session) {
        throw new Error('User session is not found.')
      }

      session[authorizationKey] = undefined
    },
    /**
     * Obtains parsed id_token claims from a `TokenSet` data.
     * @param {object} param0
     * @param {object} param0.tokenSet
     * @returns {object}
     * @alias module:openid-client-helper#getClaims
     */
    getClaims: ({
      tokenSet
    } = {}) => {
      return (new TokenSet(tokenSet)).claims()
    },
    /**
     * Returns attributes of the WWW-Authenticate response header from an HTTP response object.
     * @param {object} response An HTTP response to derive WWW-Authenticate header from.
     * @returns {object} Attributes found in the header.
     * @alias module:openid-client-helper#getWWWAuthenticateHeaderAttributes
     */
    getWWWAuthenticateHeaderAttributes: (response) => {
      const header = response.headers.get('www-authenticate')
      const scheme = /^Bearer /

      if (!header || !header.match(scheme)) {
        return {}
      }

      return header.replace(scheme, '')
      .replace(/ /g, '')
      .match(/[^,=]+=".*?"/g)
      .reduce((attributes, attribute) => {
        const pair = attribute.split('=')
        .map((e) => { return e.replace(/"(.*)"/, '$1') })

        attributes[pair[0]] = pair[1]

        return attributes
      }, {})
    }
  }

  return helper
}
