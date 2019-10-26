# Express.js example

0. Installation

    Navigate to the example subdirectory:

    ```bash
    cd examples/express
    ```

    Then:

    ```bash
    npm install
    ```

0. Collect the openid-client [Issuer](https://github.com/panva/node-openid-client/tree/master/docs#issuer) metadata.

    The issuer configuration can be automatically discovered via the `.well-known` URI, if the configuration document is made available online by the OpenID provider. In this case, the issuer location, as described in the [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) docs, could be provided as the `issuer` property value in the metadata.

    If your  provider does not support OpenID Connect Discovery, at a minimum, you will need values for the following metadata properties:

    * `issuer`
    * `authorization_endpoint`
    * `token_endpoint`

0. Collect the openid-client [Client](https://github.com/panva/node-openid-client/tree/master/docs#client) metadata.

    Note that URIs used below will need to be registered for your Client with the Issuer; otherwise, you may need to change the URIs in the configuration object, as well as the host and the port you run the sample application on.

0. Provide your values in the configuration object in [index.js](index.js):

    ```javascript
    // . . .

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

    // . . .
    ```

0. Change the example resource URI according to your `resources` configuration:

    ```javascript
    // . . .

    // Fetch.
    app.get('/protected', (req, res) => {
      var content = '<p><a href="/">Home</a></p>'

      content += '<p><a href="/deauthorize">Deauthorize</a></p>'

      fetch(
        'https://server.example.com/resource', // An abstract URI; replace it with an actual resource.
        undefined,
        req
      )

      // . . .
    })

    // . . .
    ```

0. Run the application:

    ```bash
    node index.js
    ```

0. Visit the application in your browser at [http://localhost:3333](http://localhost:3333).

The behavior of your application may depend on your Client and Issuer specifics.