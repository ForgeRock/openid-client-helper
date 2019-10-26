'use strict'

// FOR DEVELOPMENT ONLY: allow for self-signed/invalid certificates universally
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

// Use Express.js for routing.
const express = require('express')
var session = require('express-session')

const app = express()

app.use(session({
  secret: 'CHANGE-IT',
  resave: false,
  saveUninitialized: true,
  cookie: {}
}))

// Import
const helper = require('openid-client-helper')

// // A ForgeRock configuration example.
// const issuerMetadata = {
//   issuer: 'https://default.iam.example.com/am/oauth2',
//   revocation_endpoint: 'https://default.iam.example.com/am/oauth2/token/revoke' // A property not exposed in the OpenID configuration document.
// }
// const clientMetadata = {
//   client_id: 'node-openid-client',
//   client_secret: 'password',
//   // token_endpoint_auth_method: 'client_secret_post', // The default is 'client_secret_basic'.
//   redirect_uri: 'http://localhost:3333/redirect',
//   post_logout_redirect_uri: 'http://localhost:3333'
// }
// const resources = {
//   'https://default.iam.example.com/openidm/info/login': {
//     scope: 'fr:idm:profile'
//   }
// }

// // A Google configuration example.
// const issuerMetadata = {
//   issuer: 'https://accounts.google.com'
// }
// const clientMetadata = {
//   client_id: 'google-client.apps.googleusercontent.com',
//   client_secret: 'google-client-secret',
//   // token_endpoint_auth_method: 'client_secret_post', // The default is 'client_secret_basic'.
//   redirect_uri: 'http://localhost:3333/redirect'
//   // `Google` does not support RP-initiated logout.
// }
// const resources = {
//   'https://openidconnect.googleapis.com/v1/userinfo': {
//     scope: 'https://www.googleapis.com/auth/userinfo.profile'
//   }
// }

// Abstract configuration example.
const issuerMetadata = {
  issuer: 'http://openid.net/specs/connect/1.0/issuer/.well-known/openid-configuration'
}
const clientMetadata = {
  client_id: 'client-id',
  client_secret: 'client-secret',
  // token_endpoint_auth_method: 'client_secret_post', // The default is 'client_secret_basic'.
  redirect_uri: 'http://localhost:3333/redirect',
  post_logout_redirect_uri: 'http://localhost:3333'
}
const resources = {
  'https://server.example.com': {
    scope: 'profile'
  }
}

// Configure.
const {
  authorize,
  redirect,
  deauthorize,
  getAuthorization,
  fetch
} = helper({
  issuerMetadata,
  clientMetadata,
  resources
})

// Home.
app.get('/', (req, res, next) => {
  res.send('<a href="/authorize">Authorize</a>')
})

// Authorize.
app.get('/authorize', authorize({
  // An example of a special authorization parameter.
  // In this case, it would instruct `Google` to issue a refresh token (for "offline" use).
  access_type: 'offline'
}))

// Token request.
app.get('/redirect', redirect(), (req, res) => {
  res.redirect('/protected')
})

// Fetch.
app.get('/protected', (req, res) => {
  var content = '<p><a href="/">Home</a></p>'

  content += '<p><a href="/deauthorize">Deauthorize</a></p>'

  fetch(
    'https://server.example.com/resource', // An abstract URI; replace it with an actual resource.
    undefined,
    req
  )
  .then((response) => {
    var responseData

    const responseClone = response.clone()

    return response.json()
    .then((data) => {
      responseData = data
    })
    .catch((e) => {
      responseClone.text()
      .then((data) => {
        responseData = data
      })
    })
    .finally(() => {
      content += '<pre>' +
      '<p>Authorization: </p>' +
      JSON.stringify(getAuthorization({
        req
      }), null, 2) +
      '</pre>'

      content += '<pre>' +
      '<p>Fetch response: </p>' +
      JSON.stringify(responseData, null, 2) +
      '</pre>'
    })
  })
  .catch((e) => {
    content += e.message
  })
  .finally(() => {
    res.send(content)
  })
})

// Deauthorize.
app.get('/deauthorize', deauthorize(), (req, res) => {
  res.redirect('/')
})

const listener = app.listen(3333, () => {
  console.log(`Listening on port: ${listener.address().port}`)
})
