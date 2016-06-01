// import 'xtend';
// import 'popsicle';
// import 'querystring';
// import 'url';
System.register([], function(exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    var hasOwnProperty, extend, DEFAULT_HEADERS, ERROR_RESPONSES, ClientOAuth2, ClientOAuth2Token, TokenFlow;
    /**
     * Check if properties exist on an object and throw when they aren't.
     *
     * @throws {TypeError} If an expected property is missing.
     *
     * @param {Object} obj
     * @param {Array}  props
     */
    function expects(obj, props) {
        for (var i = 0; i < props.length; i++) {
            var prop = props[i];
            if (obj[prop] == null) {
                throw new TypeError('Expected "' + prop + '" to exist');
            }
        }
    }
    /**
     * Pull an authentication error from the response data.
     *
     * @param  {Object} data
     * @return {String}
     */
    function getAuthError(data) {
        var message = ERROR_RESPONSES[data.error] ||
            data.error ||
            data.error_message;
        // Return an error instance with the message if it exists.
        return message && new Error(message);
    }
    /**
     * Handle the authentication response object.
     *
     * @param  {Object}  res
     * @return {Promise}
     */
    function handleAuthResponse(res) {
        var data = res.body;
        var err = getAuthError(data);
        // If the response contains an error, reject the refresh token.
        if (err) {
            return err;
        }
        return data;
    }
    /**
     * Sanitize the scopes option to be a string.
     *
     * @param  {Array}  scopes
     * @return {String}
     */
    function sanitizeScope(scopes) {
        return Array.isArray(scopes) ? scopes.join(' ') : string(scopes);
    }
    /**
     * Create a request uri based on an options object and token type.
     *
     * @param  {Object} options
     * @param  {String} tokenType
     * @return {String}
     */
    function createUri(options, tokenType) {
        // Check the required parameters are set.
        expects(options, [
            'clientId',
            'redirectUri',
            'authorizationUri'
        ]);
        var clientId = encodeURIComponent(options.clientId);
        var redirectUri = encodeURIComponent(options.redirectUri);
        var scopes = encodeURIComponent(sanitizeScope(options.scopes));
        var uri = options.authorizationUri + '?client_id=' + clientId +
            '&redirect_uri=' + redirectUri +
            '&scope=' + scopes +
            '&response_type=' + tokenType;
        if (options.state) {
            uri += '&state=' + encodeURIComponent(options.state);
        }
        return uri;
    }
    /**
     * Create basic auth header.
     *
     * @param  {String} username
     * @param  {String} password
     * @return {String}
     */
    function auth(username, password) {
        return 'Basic ' + btoa(string(username) + ':' + string(password));
    }
    /**
     * Ensure a value is a string.
     *
     * @param  {String} str
     * @return {String}
     */
    function string(str) {
        return str == null ? '' : String(str);
    }
    /**
     * Merge request options from an options object.
     */
    function requestOptions(requestOptions, options) {
        return extend(requestOptions, {
            body: extend(options.body, requestOptions.body),
            query: extend(options.query, requestOptions.query),
            headers: extend(options.headers, requestOptions.headers),
            options: extend(options.options, requestOptions.options)
        });
    }
    return {
        setters:[],
        execute: function() {
            hasOwnProperty = Object.prototype.hasOwnProperty;
            extend = function extend() {
                var args = [];
                for (var _i = 0; _i < arguments.length; _i++) {
                    args[_i - 0] = arguments[_i];
                }
                var target = {};
                for (var i = 0; i < args.length; i++) {
                    var source = args[i];
                    for (var key in source) {
                        if (hasOwnProperty.call(source, key)) {
                            target[key] = source[key];
                        }
                    }
                }
                return target;
            };
            //var popsicle  :any;
            //var parseQuery :any;
            //var parseUrl  :any;
            // var extend = require('xtend')
            // var popsicle = require('popsicle')
            // var parseQuery = require('querystring').parse
            // var parseUrl = require('url').parse
            //var btoa = typeof Buffer === 'function' ? btoaBuffer : window.btoa
            /**
             * Default headers for executing OAuth 2.0 flows.
             *
             * @type {Object}
             */
            DEFAULT_HEADERS = {
                'Accept': 'application/json, application/x-www-form-urlencoded',
                'Content-Type': 'application/x-www-form-urlencoded'
            };
            /**
             * Format error response types to regular strings for displaying to clients.
             *
             * Reference: http://tools.ietf.org/html/rfc6749#section-4.1.2.1
             *
             * @type {Object}
             */
            ERROR_RESPONSES = {
                'invalid_request': [
                    'The request is missing a required parameter, includes an',
                    'invalid parameter value, includes a parameter more than',
                    'once, or is otherwise malformed.'
                ].join(' '),
                'invalid_client': [
                    'Client authentication failed (e.g., unknown client, no',
                    'client authentication included, or unsupported',
                    'authentication method).'
                ].join(' '),
                'invalid_grant': [
                    'The provided authorization grant (e.g., authorization',
                    'code, resource owner credentials) or refresh token is',
                    'invalid, expired, revoked, does not match the redirection',
                    'URI used in the authorization request, or was issued to',
                    'another client.'
                ].join(' '),
                'unauthorized_client': [
                    'The client is not authorized to request an authorization',
                    'code using this method.'
                ].join(' '),
                'unsupported_grant_type': [
                    'The authorization grant type is not supported by the',
                    'authorization server.'
                ].join(' '),
                'access_denied': [
                    'The resource owner or authorization server denied the request.'
                ].join(' '),
                'unsupported_response_type': [
                    'The authorization server does not support obtaining',
                    'an authorization code using this method.'
                ].join(' '),
                'invalid_scope': [
                    'The requested scope is invalid, unknown, or malformed.'
                ].join(' '),
                'server_error': [
                    'The authorization server encountered an unexpected',
                    'condition that prevented it from fulfilling the request.',
                    '(This error code is needed because a 500 Internal Server',
                    'Error HTTP status code cannot be returned to the client',
                    'via an HTTP redirect.)'
                ].join(' '),
                'temporarily_unavailable': [
                    'The authorization server is currently unable to handle',
                    'the request due to a temporary overloading or maintenance',
                    'of the server.'
                ].join(' ')
            };
            ;
            /**
             * Construct an object that can handle the multiple OAuth 2.0 flows.
             *
             * @param {Object} options
             */
            ClientOAuth2 = (function () {
                function ClientOAuth2(options) {
                    this.options = options;
                    // this.code = new CodeFlow(this);
                    this.token = new TokenFlow(this);
                    // this.owner = new OwnerFlow(this);
                    // this.credentials = new CredentialsFlow(this);
                    // this.jwt = new JwtBearerFlow(this);
                }
                ClientOAuth2.prototype.createToken = function (access, refresh, type, data) {
                    var options = extend(data, typeof access === 'string' ? { access_token: access } : access, typeof refresh === 'string' ? { refresh_token: refresh } : refresh, typeof type === 'string' ? { token_type: type } : type);
                    return new ClientOAuth2Token(this, options);
                };
                ClientOAuth2.prototype._request = function (requestObject) {
                    var request = new XMLHttpRequest();
                    var headers = requestObject.headers;
                    for (var header in headers) {
                        request.setRequestHeader(header, headers[header]);
                    }
                    request.open(requestObject.method, requestObject.url, false);
                    request.send(requestObject.body);
                    return request.response;
                    //   return this.request(requestObject)
                    //     .then(function (res) {
                    //       if (res.status < 200 || res.status >= 399) {
                    //         var err = new Error('HTTP status ' + res.status)
                    //         err.status = res.status
                    //         err.body = res.body
                    //         return Promise.reject(err)
                    //       }
                    //       return res
                    //     })
                };
                return ClientOAuth2;
            }());
            exports_1("ClientOAuth2", ClientOAuth2);
            /**
             * Alias the token constructor.
             *
             * @type {Function}
             */
            //ClientOAuth2.Token = ClientOAuth2Token
            /**
             * Using the built-in request method, we'll automatically attempt to parse
             * the response.
             *
             * @param  {Object}  requestObject
             * @return {Promise}
             */
            // /**
            //  * Set `popsicle` as the default request method.
            //  */
            // ClientOAuth2.prototype.request = popsicle.request
            /**
             * General purpose client token generator.
             *
             * @param {Object} client
             * @param {Object} data
             */
            ClientOAuth2Token = (function () {
                function ClientOAuth2Token(client, data) {
                    this.client = client;
                    this.data = data;
                    this.tokenType = data.token_type && data.token_type.toLowerCase();
                    this.accessToken = data.access_token;
                    this.refreshToken = data.refresh_token;
                    this.expiresIn(data.expires_in);
                }
                ClientOAuth2Token.prototype.expiresIn = function (duration) {
                    if (!isNaN(duration)) {
                        this.expires = new Date();
                        this.expires.setSeconds(this.expires.getSeconds() + duration);
                    }
                    else {
                        this.expires = undefined;
                    }
                    return this.expires;
                };
                ClientOAuth2Token.prototype.sign = function (requestObject) {
                    if (!this.accessToken) {
                        throw new Error('Unable to sign without access token');
                    }
                    requestObject.headers = requestObject.headers || {};
                    if (this.tokenType === 'bearer') {
                        requestObject.headers.Authorization = 'Bearer ' + this.accessToken;
                    }
                    else {
                        var parts = requestObject.url.split('#');
                        var token = 'access_token=' + this.accessToken;
                        var url = parts[0].replace(/[?&]access_token=[^&#]/, '');
                        var fragment = parts[1] ? '#' + parts[1] : '';
                        // Prepend the correct query string parameter to the url.
                        requestObject.url = url + (url.indexOf('?') > -1 ? '&' : '?') + token + fragment;
                        // Attempt to avoid storing the url in proxies, since the access token
                        // is exposed in the query parameters.
                        requestObject.headers.Pragma = 'no-store';
                        requestObject.headers['Cache-Control'] = 'no-store';
                    }
                    return requestObject;
                };
                ClientOAuth2Token.prototype.request = function (options) {
                    var requestOptionsResult = requestOptions(this.sign(options), this.client.options);
                    return this.client._request(requestOptionsResult);
                };
                ClientOAuth2Token.prototype.refresh = function (options) {
                    var self = this;
                    options = extend(this.client.options, options);
                    if (!this.refreshToken) {
                        return new Error('No refresh token set');
                    }
                    var response = this.client._request(requestOptions({
                        url: options.accessTokenUri,
                        method: 'POST',
                        headers: extend(DEFAULT_HEADERS, {
                            Authorization: auth(options.clientId, options.clientSecret)
                        }),
                        body: {
                            refresh_token: this.refreshToken,
                            grant_type: 'refresh_token'
                        }
                    }, options));
                    var body = handleAuthResponse(response);
                    //TODO: Tratar quando exception
                    var retorno = (function (data) {
                        self.accessToken = data.access_token;
                        self.refreshToken = data.refresh_token;
                        self.expiresIn(data.expires_in);
                        return self;
                    })(body);
                    return retorno;
                };
                Object.defineProperty(ClientOAuth2Token.prototype, "expired", {
                    get: function () {
                        if (this.expires) {
                            return Date.now() > this.expires.getTime();
                        }
                        return false;
                    },
                    enumerable: true,
                    configurable: true
                });
                return ClientOAuth2Token;
            }());
            exports_1("ClientOAuth2Token", ClientOAuth2Token);
            // /**
            //  * Support resource owner password credentials OAuth 2.0 grant.
            //  *
            //  * Reference: http://tools.ietf.org/html/rfc6749#section-4.3
            //  *
            //  * @param {ClientOAuth2} client
            //  */
            // function OwnerFlow (client) {
            //   this.client = client
            // }
            // /**
            //  * Make a request on behalf of the user credentials to get an acces token.
            //  *
            //  * @param  {String}  username
            //  * @param  {String}  password
            //  * @return {Promise}
            //  */
            // OwnerFlow.prototype.getToken = function (username, password, options) {
            //   var self = this
            //   options = extend(this.client.options, options)
            //   return this.client._request(requestOptions({
            //     url: options.accessTokenUri,
            //     method: 'POST',
            //     headers: extend(DEFAULT_HEADERS, {
            //       Authorization: auth(options.clientId, options.clientSecret)
            //     }),
            //     body: {
            //       scope: sanitizeScope(options.scopes),
            //       username: username,
            //       password: password,
            //       grant_type: 'password'
            //     }
            //   }, options))
            //     .then(handleAuthResponse)
            //     .then(function (data) {
            //       return new ClientOAuth2Token(self.client, data)
            //     })
            // }
            /**
             * Support implicit OAuth 2.0 grant.
             *
             * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
             *
             * @param {ClientOAuth2} client
             */
            TokenFlow = (function () {
                function TokenFlow(client) {
                    this.client = client;
                }
                TokenFlow.prototype.getUri = function (options) {
                    options = extend(this.client.options, options);
                    return createUri(options, 'token');
                };
                TokenFlow.prototype.getToken = function (uri, state, options) {
                    //options = extend(this.client.options, options);
                    // var url = parseUrl(uri)
                    // var expectedUrl = parseUrl(options.redirectUri)
                    // if (url.pathname !== expectedUrl.pathname) {
                    //     return Promise.reject(new TypeError('Should match redirect uri: ' + uri))
                    // }
                    // // If no query string or fragment exists, we won't be able to parse
                    // // any useful information from the uri.
                    // if (!url.hash && !url.search) {
                    //     return Promise.reject(new TypeError('Unable to process uri: ' + uri))
                    // }
                    // Extract data from both the fragment and query string. The fragment is most
                    // important, but the query string is also used because some OAuth 2.0
                    // implementations (Instagram) have a bug where state is passed via query.
                    // var data = extend(
                    //     url.query ? parseQuery(url.query) : {},
                    //     url.hash ? parseQuery(url.hash.substr(1)) : {}
                    // )
                    // var err = getAuthError(data)
                    // // Check if the query string was populated with a known error.
                    // if (err) {
                    //     return Promise.reject(err)
                    // }
                    // // Check whether the state matches.
                    // if (state != null && data.state !== state) {
                    //     return Promise.reject(new TypeError('Invalid state: ' + data.state))
                    // }
                    function ParsearUrl(url) {
                        if (url.indexOf('#') !== -1) {
                            return url.substr(url.indexOf('#'), url.length).replace('?', '').replace('#', '').split('&').reduce(function (s, c) { var t = c.split('='); s[t[0]] = t[1]; return s; }, {});
                        }
                        else {
                            return url.substr(url.indexOf('?'), url.length).replace('?', '').replace('#', '').split('&').reduce(function (s, c) { var t = c.split('='); s[t[0]] = t[1]; return s; }, {});
                        }
                    }
                    var urlParseada = ParsearUrl(uri);
                    var data = urlParseada;
                    // Initalize a new token and return.
                    return new ClientOAuth2Token(this.client, data);
                };
                return TokenFlow;
            }());
            exports_1("TokenFlow", TokenFlow);
        }
    }
});
// /**
//  * Support client credentials OAuth 2.0 grant.
//  *
//  * Reference: http://tools.ietf.org/html/rfc6749#section-4.4
//  *
//  * @param {ClientOAuth2} client
//  */
// function CredentialsFlow (client) {
//   this.client = client
// }
// /**
//  * Request an access token using the client credentials.
//  *
//  * @param  {Object}  [options]
//  * @return {Promise}
//  */
// CredentialsFlow.prototype.getToken = function (options) {
//   var self = this
//   options = extend(this.client.options, options)
//   expects(options, [
//     'clientId',
//     'clientSecret',
//     'accessTokenUri'
//   ])
//   return this.client._request(requestOptions({
//     url: options.accessTokenUri,
//     method: 'POST',
//     headers: extend(DEFAULT_HEADERS, {
//       Authorization: auth(options.clientId, options.clientSecret)
//     }),
//     body: {
//       scope: sanitizeScope(options.scopes),
//       grant_type: 'client_credentials'
//     }
//   }, options))
//     .then(handleAuthResponse)
//     .then(function (data) {
//       return new ClientOAuth2Token(self.client, data)
//     })
// }
// /**
//  * Support authorization code OAuth 2.0 grant.
//  *
//  * Reference: http://tools.ietf.org/html/rfc6749#section-4.1
//  *
//  * @param {ClientOAuth2} client
//  */
// function CodeFlow (client) {
//   this.client = client
// }
// /**
//  * Generate the uri for doing the first redirect.
//  *
//  * @return {String}
//  */
// CodeFlow.prototype.getUri = function (options) {
//   options = extend(this.client.options, options)
//   return createUri(options, 'code')
// }
// /**
//  * Get the code token from the redirected uri and make another request for
//  * the user access token.
//  *
//  * @param  {String}  uri
//  * @param  {String}  [state]
//  * @param  {Object}  [options]
//  * @return {Promise}
//  */
// CodeFlow.prototype.getToken = function (uri, state, options) {
//   var self = this
//   options = extend(this.client.options, options)
//   expects(options, [
//     'clientId',
//     'clientSecret',
//     'redirectUri',
//     'accessTokenUri'
//   ])
//   var url = parseUrl(uri)
//   var expectedUrl = parseUrl(options.redirectUri)
//   if (url.pathname !== expectedUrl.pathname) {
//     return Promise.reject(new TypeError('Should match redirect uri: ' + uri))
//   }
//   if (!url.search) {
//     return Promise.reject(new TypeError('Unable to process uri: ' + uri))
//   }
//   var data = parseQuery(url.query)
//   var err = getAuthError(data)
//   if (err) {
//     return Promise.reject(err)
//   }
//   if (state && data.state !== state) {
//     return Promise.reject(new TypeError('Invalid state:' + data.state))
//   }
//   // Check whether the response code is set.
//   if (!data.code) {
//     return Promise.reject(new TypeError('Missing code, unable to request token'))
//   }
//   return this.client._request(requestOptions({
//     url: options.accessTokenUri,
//     method: 'POST',
//     headers: extend(DEFAULT_HEADERS),
//     body: {
//       code: data.code,
//       grant_type: 'authorization_code',
//       redirect_uri: options.redirectUri,
//       client_id: options.clientId,
//       client_secret: options.clientSecret
//     }
//   }, options))
//     .then(handleAuthResponse)
//     .then(function (data) {
//       return new ClientOAuth2Token(self.client, data)
//     })
// }
// /**
//  * Support JSON Web Token (JWT) Bearer Token OAuth 2.0 grant.
//  *
//  * Reference: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1
//  *
//  * @param {ClientOAuth2} client
//  */
// function JwtBearerFlow (client) {
//   this.client = client
// }
// /**
//  * Request an access token using a JWT token.
//  *
//  * @param  {string} token A JWT token.
//  * @param  {Object}  [options]
//  * @return {Promise}
//  */
// JwtBearerFlow.prototype.getToken = function (token, options) {
//   var self = this
//   options = extend(this.client.options, options)
//   expects(options, [
//     'accessTokenUri'
//   ])
//   var headers = extend(DEFAULT_HEADERS)
//   // Authentication of the client is optional, as described in
//   // Section 3.2.1 of OAuth 2.0 [RFC6749]
//   if (options.clientId) {
//     headers['Authorization'] = auth(options.clientId, options.clientSecret)
//   }
//   return this.client._request(requestOptions({
//     url: options.accessTokenUri,
//     method: 'POST',
//     headers: headers,
//     body: {
//       scope: sanitizeScope(options.scopes),
//       grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
//       assertion: token
//     }
//   }, options))
//     .then(handleAuthResponse)
//     .then(function (data) {
//       return new ClientOAuth2Token(self.client, data)
//     })
// }

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9DbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsa0JBQWtCO0FBQ2xCLHFCQUFxQjtBQUNyQix3QkFBd0I7QUFDeEIsZ0JBQWdCOzs7O1FBRVosY0FBYyxFQUVkLE1BQU0sRUFrQ04sZUFBZSxFQVlmLGVBQWU7SUFtRG5COzs7Ozs7O09BT0c7SUFDSCxpQkFBa0IsR0FBRyxFQUFFLEtBQUs7UUFDMUIsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUM7WUFDdEMsSUFBSSxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBRW5CLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDO2dCQUN0QixNQUFNLElBQUksU0FBUyxDQUFDLFlBQVksR0FBRyxJQUFJLEdBQUcsWUFBWSxDQUFDLENBQUE7WUFDekQsQ0FBQztRQUNILENBQUM7SUFDSCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxzQkFBdUIsSUFBSTtRQUN6QixJQUFJLE9BQU8sR0FBRyxlQUFlLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQztZQUN2QyxJQUFJLENBQUMsS0FBSztZQUNWLElBQUksQ0FBQyxhQUFhLENBQUE7UUFFcEIsMERBQTBEO1FBQzFELE1BQU0sQ0FBQyxPQUFPLElBQUksSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7SUFDdEMsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsNEJBQTZCLEdBQUc7UUFDOUIsSUFBSSxJQUFJLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQztRQUNwQixJQUFJLEdBQUcsR0FBRyxZQUFZLENBQUMsSUFBSSxDQUFDLENBQUM7UUFFN0IsK0RBQStEO1FBQy9ELEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDUixNQUFNLENBQUMsR0FBRyxDQUFDO1FBQ2IsQ0FBQztRQUVELE1BQU0sQ0FBQyxJQUFJLENBQUM7SUFDZCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCx1QkFBd0IsTUFBTTtRQUM1QixNQUFNLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUNuRSxDQUFDO0lBRUQ7Ozs7OztPQU1HO0lBQ0gsbUJBQW9CLE9BQU8sRUFBRSxTQUFTO1FBQ3BDLHlDQUF5QztRQUN6QyxPQUFPLENBQUMsT0FBTyxFQUFFO1lBQ2YsVUFBVTtZQUNWLGFBQWE7WUFDYixrQkFBa0I7U0FDbkIsQ0FBQyxDQUFDO1FBRUgsSUFBSSxRQUFRLEdBQUcsa0JBQWtCLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3BELElBQUksV0FBVyxHQUFHLGtCQUFrQixDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUMxRCxJQUFJLE1BQU0sR0FBRyxrQkFBa0IsQ0FBQyxhQUFhLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7UUFDL0QsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLGdCQUFnQixHQUFHLGFBQWEsR0FBRyxRQUFRO1lBQzNELGdCQUFnQixHQUFHLFdBQVc7WUFDOUIsU0FBUyxHQUFHLE1BQU07WUFDbEIsaUJBQWlCLEdBQUcsU0FBUyxDQUFDO1FBRWhDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQ2xCLEdBQUcsSUFBSSxTQUFTLEdBQUcsa0JBQWtCLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3ZELENBQUM7UUFFRCxNQUFNLENBQUMsR0FBRyxDQUFDO0lBQ2IsQ0FBQztJQUVEOzs7Ozs7T0FNRztJQUNILGNBQWUsUUFBUSxFQUFFLFFBQVE7UUFDL0IsTUFBTSxDQUFDLFFBQVEsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxHQUFHLEdBQUcsR0FBRyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUNwRSxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxnQkFBaUIsR0FBRztRQUNsQixNQUFNLENBQUMsR0FBRyxJQUFJLElBQUksR0FBRyxFQUFFLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3hDLENBQUM7SUFXRDs7T0FFRztJQUNILHdCQUF5QixjQUFjLEVBQUUsT0FBTztRQUU5QyxNQUFNLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRTtZQUM1QixJQUFJLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxJQUFJLEVBQUUsY0FBYyxDQUFDLElBQUksQ0FBQztZQUMvQyxLQUFLLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsY0FBYyxDQUFDLEtBQUssQ0FBQztZQUNsRCxPQUFPLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsY0FBYyxDQUFDLE9BQU8sQ0FBQztZQUN4RCxPQUFPLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsY0FBYyxDQUFDLE9BQU8sQ0FBQztTQUN6RCxDQUFDLENBQUM7SUFDTCxDQUFDOzs7O1lBdk9HLGNBQWMsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQztZQUVqRCxNQUFNLEdBQUc7Z0JBQWdCLGNBQWtCO3FCQUFsQixXQUFrQixDQUFsQixzQkFBa0IsQ0FBbEIsSUFBa0I7b0JBQWxCLDZCQUFrQjs7Z0JBQzNDLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQTtnQkFFZixHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQztvQkFDbkMsSUFBSSxNQUFNLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFBO29CQUVwQixHQUFHLENBQUMsQ0FBQyxJQUFJLEdBQUcsSUFBSSxNQUFNLENBQUMsQ0FBQyxDQUFDO3dCQUNyQixFQUFFLENBQUMsQ0FBQyxjQUFjLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7NEJBQ25DLE1BQU0sQ0FBQyxHQUFHLENBQUMsR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7d0JBQzdCLENBQUM7b0JBQ0wsQ0FBQztnQkFDTCxDQUFDO2dCQUVELE1BQU0sQ0FBQyxNQUFNLENBQUM7WUFDbEIsQ0FBQyxDQUFBO1lBSUQscUJBQXFCO1lBQ3JCLHNCQUFzQjtZQUN0QixxQkFBcUI7WUFFckIsZ0NBQWdDO1lBQ2hDLHFDQUFxQztZQUNyQyxnREFBZ0Q7WUFDaEQsc0NBQXNDO1lBRXRDLG9FQUFvRTtZQUVwRTs7OztlQUlHO1lBQ0MsZUFBZSxHQUFHO2dCQUNwQixRQUFRLEVBQUUscURBQXFEO2dCQUMvRCxjQUFjLEVBQUUsbUNBQW1DO2FBQ3BELENBQUE7WUFFRDs7Ozs7O2VBTUc7WUFDQyxlQUFlLEdBQUc7Z0JBQ3BCLGlCQUFpQixFQUFFO29CQUNqQiwwREFBMEQ7b0JBQzFELHlEQUF5RDtvQkFDekQsa0NBQWtDO2lCQUNuQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsZ0JBQWdCLEVBQUU7b0JBQ2hCLHdEQUF3RDtvQkFDeEQsZ0RBQWdEO29CQUNoRCx5QkFBeUI7aUJBQzFCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxlQUFlLEVBQUU7b0JBQ2YsdURBQXVEO29CQUN2RCx1REFBdUQ7b0JBQ3ZELDJEQUEyRDtvQkFDM0QseURBQXlEO29CQUN6RCxpQkFBaUI7aUJBQ2xCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxxQkFBcUIsRUFBRTtvQkFDckIsMERBQTBEO29CQUMxRCx5QkFBeUI7aUJBQzFCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCx3QkFBd0IsRUFBRTtvQkFDeEIsc0RBQXNEO29CQUN0RCx1QkFBdUI7aUJBQ3hCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxlQUFlLEVBQUU7b0JBQ2YsZ0VBQWdFO2lCQUNqRSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsMkJBQTJCLEVBQUU7b0JBQzNCLHFEQUFxRDtvQkFDckQsMENBQTBDO2lCQUMzQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsZUFBZSxFQUFFO29CQUNmLHdEQUF3RDtpQkFDekQsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO2dCQUNYLGNBQWMsRUFBRTtvQkFDZCxvREFBb0Q7b0JBQ3BELDBEQUEwRDtvQkFDMUQsMERBQTBEO29CQUMxRCx5REFBeUQ7b0JBQ3pELHdCQUF3QjtpQkFDekIsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO2dCQUNYLHlCQUF5QixFQUFFO29CQUN6Qix3REFBd0Q7b0JBQ3hELDJEQUEyRDtvQkFDM0QsZ0JBQWdCO2lCQUNqQixDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7YUFDWixDQUFBO1lBMEhBLENBQUM7WUFlRjs7OztlQUlHO1lBQ0g7Z0JBUUksc0JBQVksT0FBWTtvQkFFcEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUM7b0JBRXZCLGtDQUFrQztvQkFDbEMsSUFBSSxDQUFDLEtBQUssR0FBRyxJQUFJLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQztvQkFDakMsb0NBQW9DO29CQUNwQyxnREFBZ0Q7b0JBQ2hELHNDQUFzQztnQkFDMUMsQ0FBQztnQkFFTSxrQ0FBVyxHQUFsQixVQUFtQixNQUFjLEVBQUUsT0FBZSxFQUFFLElBQVksRUFBRSxJQUFTO29CQUV2RSxJQUFJLE9BQU8sR0FBRyxNQUFNLENBQ2hCLElBQUksRUFDSixPQUFPLE1BQU0sS0FBSyxRQUFRLEdBQUcsRUFBRSxZQUFZLEVBQUUsTUFBTSxFQUFFLEdBQUcsTUFBTSxFQUM5RCxPQUFPLE9BQU8sS0FBSyxRQUFRLEdBQUcsRUFBRSxhQUFhLEVBQUUsT0FBTyxFQUFFLEdBQUcsT0FBTyxFQUNsRSxPQUFPLElBQUksS0FBSyxRQUFRLEdBQUcsRUFBRSxVQUFVLEVBQUUsSUFBSSxFQUFFLEdBQUcsSUFBSSxDQUN6RCxDQUFDO29CQUVGLE1BQU0sQ0FBQyxJQUFJLGlCQUFpQixDQUFDLElBQUksRUFBRSxPQUFPLENBQUMsQ0FBQztnQkFDaEQsQ0FBQztnQkFFTSwrQkFBUSxHQUFmLFVBQWdCLGFBQThCO29CQUUxQyxJQUFJLE9BQU8sR0FBRyxJQUFJLGNBQWMsRUFBRSxDQUFDO29CQUVuQyxJQUFJLE9BQU8sR0FBRyxhQUFhLENBQUMsT0FBTyxDQUFDO29CQUNwQyxHQUFHLENBQUEsQ0FBQyxJQUFJLE1BQU0sSUFBSSxPQUFPLENBQUMsQ0FDMUIsQ0FBQzt3QkFDRyxPQUFPLENBQUMsZ0JBQWdCLENBQUMsTUFBTSxFQUFFLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO29CQUN0RCxDQUFDO29CQUVELE9BQU8sQ0FBQyxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU0sRUFBRSxhQUFhLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQyxDQUFDO29CQUU3RCxPQUFPLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQztvQkFFakMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUM7b0JBRTVCLHVDQUF1QztvQkFDdkMsNkJBQTZCO29CQUM3QixxREFBcUQ7b0JBQ3JELDJEQUEyRDtvQkFDM0Qsa0NBQWtDO29CQUNsQyw4QkFBOEI7b0JBQzlCLHFDQUFxQztvQkFDckMsVUFBVTtvQkFFVixtQkFBbUI7b0JBQ25CLFNBQVM7Z0JBQ1QsQ0FBQztnQkFDTCxtQkFBQztZQUFELENBM0RBLEFBMkRDLElBQUE7WUEzREQsdUNBMkRDLENBQUE7WUFFRDs7OztlQUlHO1lBQ0gsd0NBQXdDO1lBR3hDOzs7Ozs7ZUFNRztZQUdILE1BQU07WUFDTixtREFBbUQ7WUFDbkQsTUFBTTtZQUNOLG9EQUFvRDtZQUVwRDs7Ozs7ZUFLRztZQUNIO2dCQVdJLDJCQUFZLE1BQU0sRUFBRSxJQUFJO29CQUNwQixJQUFJLENBQUMsTUFBTSxHQUFHLE1BQU0sQ0FBQztvQkFDckIsSUFBSSxDQUFDLElBQUksR0FBRyxJQUFJLENBQUM7b0JBQ2pCLElBQUksQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFDLFVBQVUsSUFBSSxJQUFJLENBQUMsVUFBVSxDQUFDLFdBQVcsRUFBRSxDQUFDO29CQUNsRSxJQUFJLENBQUMsV0FBVyxHQUFHLElBQUksQ0FBQyxZQUFZLENBQUM7b0JBQ3JDLElBQUksQ0FBQyxZQUFZLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQztvQkFFdkMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUM7Z0JBQ3BDLENBQUM7Z0JBR00scUNBQVMsR0FBaEIsVUFBaUIsUUFBUTtvQkFFckIsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FDckIsQ0FBQzt3QkFDRyxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksSUFBSSxFQUFFLENBQUM7d0JBQzFCLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLEdBQUcsUUFBUSxDQUFDLENBQUM7b0JBQ2xFLENBQUM7b0JBQ0QsSUFBSSxDQUNKLENBQUM7d0JBQ0csSUFBSSxDQUFDLE9BQU8sR0FBRyxTQUFTLENBQUM7b0JBQzdCLENBQUM7b0JBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUM7Z0JBQ3hCLENBQUM7Z0JBRU0sZ0NBQUksR0FBWCxVQUFZLGFBQWE7b0JBQ3JCLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUM7d0JBQ3BCLE1BQU0sSUFBSSxLQUFLLENBQUMscUNBQXFDLENBQUMsQ0FBQTtvQkFDMUQsQ0FBQztvQkFFRCxhQUFhLENBQUMsT0FBTyxHQUFHLGFBQWEsQ0FBQyxPQUFPLElBQUksRUFBRSxDQUFBO29CQUVuRCxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsU0FBUyxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUM7d0JBQzlCLGFBQWEsQ0FBQyxPQUFPLENBQUMsYUFBYSxHQUFHLFNBQVMsR0FBRyxJQUFJLENBQUMsV0FBVyxDQUFDO29CQUN2RSxDQUFDO29CQUFDLElBQUksQ0FBQyxDQUFDO3dCQUNKLElBQUksS0FBSyxHQUFHLGFBQWEsQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO3dCQUN6QyxJQUFJLEtBQUssR0FBRyxlQUFlLEdBQUcsSUFBSSxDQUFDLFdBQVcsQ0FBQzt3QkFDL0MsSUFBSSxHQUFHLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyx3QkFBd0IsRUFBRSxFQUFFLENBQUMsQ0FBQzt3QkFDekQsSUFBSSxRQUFRLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxHQUFHLEdBQUcsR0FBRyxLQUFLLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDO3dCQUU5Qyx5REFBeUQ7d0JBQ3pELGFBQWEsQ0FBQyxHQUFHLEdBQUcsR0FBRyxHQUFHLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxHQUFHLEdBQUcsR0FBRyxDQUFDLEdBQUcsS0FBSyxHQUFHLFFBQVEsQ0FBQzt3QkFFakYsc0VBQXNFO3dCQUN0RSxzQ0FBc0M7d0JBQ3RDLGFBQWEsQ0FBQyxPQUFPLENBQUMsTUFBTSxHQUFHLFVBQVUsQ0FBQzt3QkFDMUMsYUFBYSxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUMsR0FBRyxVQUFVLENBQUM7b0JBQ3hELENBQUM7b0JBRUQsTUFBTSxDQUFDLGFBQWEsQ0FBQztnQkFDekIsQ0FBQztnQkFFTSxtQ0FBTyxHQUFkLFVBQWUsT0FBTztvQkFDbEIsSUFBSSxvQkFBb0IsR0FBRyxjQUFjLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsRUFBRSxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDO29CQUNuRixNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsb0JBQW9CLENBQUMsQ0FBQztnQkFDdEQsQ0FBQztnQkFHTSxtQ0FBTyxHQUFkLFVBQWUsT0FBTztvQkFDbEIsSUFBSSxJQUFJLEdBQUcsSUFBSSxDQUFDO29CQUVoQixPQUFPLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFDO29CQUUvQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDO3dCQUNyQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsc0JBQXNCLENBQUMsQ0FBQztvQkFDN0MsQ0FBQztvQkFHRCxJQUFJLFFBQVEsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxjQUFjLENBQUM7d0JBQy9DLEdBQUcsRUFBRSxPQUFPLENBQUMsY0FBYzt3QkFDM0IsTUFBTSxFQUFFLE1BQU07d0JBQ2QsT0FBTyxFQUFFLE1BQU0sQ0FBQyxlQUFlLEVBQUU7NEJBQ2pDLGFBQWEsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxPQUFPLENBQUMsWUFBWSxDQUFDO3lCQUMxRCxDQUFDO3dCQUNGLElBQUksRUFBRTs0QkFDTixhQUFhLEVBQUUsSUFBSSxDQUFDLFlBQVk7NEJBQ2hDLFVBQVUsRUFBRSxlQUFlO3lCQUMxQjtxQkFDSixFQUFFLE9BQU8sQ0FBQyxDQUFDLENBQUM7b0JBRWIsSUFBSSxJQUFJLEdBQUcsa0JBQWtCLENBQUMsUUFBUSxDQUFDLENBQUM7b0JBRXhDLCtCQUErQjtvQkFFL0IsSUFBSSxPQUFPLEdBQUcsQ0FBQyxVQUFVLElBQUk7d0JBQ3pCLElBQUksQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLFlBQVksQ0FBQzt3QkFDckMsSUFBSSxDQUFDLFlBQVksR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFDO3dCQUV2QyxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQzt3QkFFaEMsTUFBTSxDQUFDLElBQUksQ0FBQztvQkFDaEIsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUM7b0JBRVQsTUFBTSxDQUFDLE9BQU8sQ0FBQztnQkFDbkIsQ0FBQztnQkFFRCxzQkFBSSxzQ0FBTzt5QkFBWDt3QkFFSSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQzs0QkFDZixNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxHQUFHLElBQUksQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLENBQUE7d0JBQzlDLENBQUM7d0JBRUQsTUFBTSxDQUFDLEtBQUssQ0FBQztvQkFDakIsQ0FBQzs7O21CQUFBO2dCQUNMLHdCQUFDO1lBQUQsQ0FuSEEsQUFtSEMsSUFBQTtZQW5IRCxpREFtSEMsQ0FBQTtZQVFELE1BQU07WUFDTixrRUFBa0U7WUFDbEUsS0FBSztZQUNMLCtEQUErRDtZQUMvRCxLQUFLO1lBQ0wsa0NBQWtDO1lBQ2xDLE1BQU07WUFDTixnQ0FBZ0M7WUFDaEMseUJBQXlCO1lBQ3pCLElBQUk7WUFFSixNQUFNO1lBQ04sNkVBQTZFO1lBQzdFLEtBQUs7WUFDTCxnQ0FBZ0M7WUFDaEMsZ0NBQWdDO1lBQ2hDLHVCQUF1QjtZQUN2QixNQUFNO1lBQ04sMEVBQTBFO1lBQzFFLG9CQUFvQjtZQUVwQixtREFBbUQ7WUFFbkQsaURBQWlEO1lBQ2pELG1DQUFtQztZQUNuQyxzQkFBc0I7WUFDdEIseUNBQXlDO1lBQ3pDLG9FQUFvRTtZQUNwRSxVQUFVO1lBQ1YsY0FBYztZQUNkLDhDQUE4QztZQUM5Qyw0QkFBNEI7WUFDNUIsNEJBQTRCO1lBQzVCLCtCQUErQjtZQUMvQixRQUFRO1lBQ1IsaUJBQWlCO1lBQ2pCLGdDQUFnQztZQUNoQyw4QkFBOEI7WUFDOUIsd0RBQXdEO1lBQ3hELFNBQVM7WUFDVCxJQUFJO1lBRUo7Ozs7OztlQU1HO1lBQ0g7Z0JBSUksbUJBQVksTUFBTTtvQkFDZCxJQUFJLENBQUMsTUFBTSxHQUFHLE1BQU0sQ0FBQztnQkFDekIsQ0FBQztnQkFFTSwwQkFBTSxHQUFiLFVBQWMsT0FBWTtvQkFDdEIsT0FBTyxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQztvQkFDL0MsTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7Z0JBQ3ZDLENBQUM7Z0JBRU0sNEJBQVEsR0FBZixVQUFnQixHQUFHLEVBQUUsS0FBTSxFQUFFLE9BQVE7b0JBRWpDLGlEQUFpRDtvQkFFakQsMEJBQTBCO29CQUMxQixrREFBa0Q7b0JBRWxELCtDQUErQztvQkFDL0MsZ0ZBQWdGO29CQUNoRixJQUFJO29CQUVKLHNFQUFzRTtvQkFDdEUsMENBQTBDO29CQUMxQyxrQ0FBa0M7b0JBQ2xDLDRFQUE0RTtvQkFDNUUsSUFBSTtvQkFFSiw2RUFBNkU7b0JBQzdFLHNFQUFzRTtvQkFDdEUsMEVBQTBFO29CQUMxRSxxQkFBcUI7b0JBQ3JCLDhDQUE4QztvQkFDOUMscURBQXFEO29CQUNyRCxJQUFJO29CQUVKLCtCQUErQjtvQkFFL0IsaUVBQWlFO29CQUNqRSxhQUFhO29CQUNiLGlDQUFpQztvQkFDakMsSUFBSTtvQkFFSixzQ0FBc0M7b0JBQ3RDLCtDQUErQztvQkFDL0MsMkVBQTJFO29CQUMzRSxJQUFJO29CQUVKLG9CQUFvQixHQUFXO3dCQUUzQixFQUFFLENBQUEsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQzNCLENBQUM7NEJBQ0csTUFBTSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsRUFBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBQyxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFDLEVBQUUsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNLENBQUMsVUFBUyxDQUFDLEVBQUMsQ0FBQyxJQUFFLElBQUksQ0FBQyxHQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUEsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFBLENBQUMsRUFBQyxFQUFFLENBQUMsQ0FBQzt3QkFDbEssQ0FBQzt3QkFDRCxJQUFJLENBQ0osQ0FBQzs0QkFDRyxNQUFNLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUMsRUFBRSxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxVQUFTLENBQUMsRUFBQyxDQUFDLElBQUUsSUFBSSxDQUFDLEdBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUEsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxDQUFDO3dCQUNsSyxDQUFDO29CQUNMLENBQUM7b0JBRUQsSUFBSSxXQUFXLEdBQUcsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDO29CQUVsQyxJQUFJLElBQUksR0FBRyxXQUFXLENBQUM7b0JBRXZCLG9DQUFvQztvQkFDcEMsTUFBTSxDQUFDLElBQUksaUJBQWlCLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRSxJQUFJLENBQUMsQ0FBQztnQkFDaEQsQ0FBQztnQkFDTCxnQkFBQztZQUFELENBckVKLEFBcUVLLElBQUE7WUFyRUwsaUNBcUVLLENBQUE7Ozs7QUFFTCxNQUFNO0FBQ04saURBQWlEO0FBQ2pELEtBQUs7QUFDTCwrREFBK0Q7QUFDL0QsS0FBSztBQUNMLGtDQUFrQztBQUNsQyxNQUFNO0FBQ04sc0NBQXNDO0FBQ3RDLHlCQUF5QjtBQUN6QixJQUFJO0FBRUosTUFBTTtBQUNOLDJEQUEyRDtBQUMzRCxLQUFLO0FBQ0wsaUNBQWlDO0FBQ2pDLHVCQUF1QjtBQUN2QixNQUFNO0FBQ04sNERBQTREO0FBQzVELG9CQUFvQjtBQUVwQixtREFBbUQ7QUFFbkQsdUJBQXVCO0FBQ3ZCLGtCQUFrQjtBQUNsQixzQkFBc0I7QUFDdEIsdUJBQXVCO0FBQ3ZCLE9BQU87QUFFUCxpREFBaUQ7QUFDakQsbUNBQW1DO0FBQ25DLHNCQUFzQjtBQUN0Qix5Q0FBeUM7QUFDekMsb0VBQW9FO0FBQ3BFLFVBQVU7QUFDVixjQUFjO0FBQ2QsOENBQThDO0FBQzlDLHlDQUF5QztBQUN6QyxRQUFRO0FBQ1IsaUJBQWlCO0FBQ2pCLGdDQUFnQztBQUNoQyw4QkFBOEI7QUFDOUIsd0RBQXdEO0FBQ3hELFNBQVM7QUFDVCxJQUFJO0FBRUosTUFBTTtBQUNOLGlEQUFpRDtBQUNqRCxLQUFLO0FBQ0wsK0RBQStEO0FBQy9ELEtBQUs7QUFDTCxrQ0FBa0M7QUFDbEMsTUFBTTtBQUNOLCtCQUErQjtBQUMvQix5QkFBeUI7QUFDekIsSUFBSTtBQUVKLE1BQU07QUFDTixvREFBb0Q7QUFDcEQsS0FBSztBQUNMLHNCQUFzQjtBQUN0QixNQUFNO0FBQ04sbURBQW1EO0FBQ25ELG1EQUFtRDtBQUVuRCxzQ0FBc0M7QUFDdEMsSUFBSTtBQUVKLE1BQU07QUFDTiw2RUFBNkU7QUFDN0UsNEJBQTRCO0FBQzVCLEtBQUs7QUFDTCwyQkFBMkI7QUFDM0IsK0JBQStCO0FBQy9CLGlDQUFpQztBQUNqQyx1QkFBdUI7QUFDdkIsTUFBTTtBQUNOLGlFQUFpRTtBQUNqRSxvQkFBb0I7QUFFcEIsbURBQW1EO0FBRW5ELHVCQUF1QjtBQUN2QixrQkFBa0I7QUFDbEIsc0JBQXNCO0FBQ3RCLHFCQUFxQjtBQUNyQix1QkFBdUI7QUFDdkIsT0FBTztBQUVQLDRCQUE0QjtBQUM1QixvREFBb0Q7QUFFcEQsaURBQWlEO0FBQ2pELGdGQUFnRjtBQUNoRixNQUFNO0FBRU4sdUJBQXVCO0FBQ3ZCLDRFQUE0RTtBQUM1RSxNQUFNO0FBRU4scUNBQXFDO0FBQ3JDLGlDQUFpQztBQUVqQyxlQUFlO0FBQ2YsaUNBQWlDO0FBQ2pDLE1BQU07QUFFTix5Q0FBeUM7QUFDekMsMEVBQTBFO0FBQzFFLE1BQU07QUFFTiwrQ0FBK0M7QUFDL0Msc0JBQXNCO0FBQ3RCLG9GQUFvRjtBQUNwRixNQUFNO0FBRU4saURBQWlEO0FBQ2pELG1DQUFtQztBQUNuQyxzQkFBc0I7QUFDdEIsd0NBQXdDO0FBQ3hDLGNBQWM7QUFDZCx5QkFBeUI7QUFDekIsMENBQTBDO0FBQzFDLDJDQUEyQztBQUMzQyxxQ0FBcUM7QUFDckMsNENBQTRDO0FBQzVDLFFBQVE7QUFDUixpQkFBaUI7QUFDakIsZ0NBQWdDO0FBQ2hDLDhCQUE4QjtBQUM5Qix3REFBd0Q7QUFDeEQsU0FBUztBQUNULElBQUk7QUFFSixNQUFNO0FBQ04sZ0VBQWdFO0FBQ2hFLEtBQUs7QUFDTCx1RkFBdUY7QUFDdkYsS0FBSztBQUNMLGtDQUFrQztBQUNsQyxNQUFNO0FBQ04sb0NBQW9DO0FBQ3BDLHlCQUF5QjtBQUN6QixJQUFJO0FBRUosTUFBTTtBQUNOLGdEQUFnRDtBQUNoRCxLQUFLO0FBQ0wseUNBQXlDO0FBQ3pDLGlDQUFpQztBQUNqQyx1QkFBdUI7QUFDdkIsTUFBTTtBQUNOLGlFQUFpRTtBQUNqRSxvQkFBb0I7QUFFcEIsbURBQW1EO0FBRW5ELHVCQUF1QjtBQUN2Qix1QkFBdUI7QUFDdkIsT0FBTztBQUVQLDBDQUEwQztBQUUxQyxpRUFBaUU7QUFDakUsNENBQTRDO0FBQzVDLDRCQUE0QjtBQUM1Qiw4RUFBOEU7QUFDOUUsTUFBTTtBQUVOLGlEQUFpRDtBQUNqRCxtQ0FBbUM7QUFDbkMsc0JBQXNCO0FBQ3RCLHdCQUF3QjtBQUN4QixjQUFjO0FBQ2QsOENBQThDO0FBQzlDLG1FQUFtRTtBQUNuRSx5QkFBeUI7QUFDekIsUUFBUTtBQUNSLGlCQUFpQjtBQUNqQixnQ0FBZ0M7QUFDaEMsOEJBQThCO0FBQzlCLHdEQUF3RDtBQUN4RCxTQUFTO0FBQ1QsSUFBSSIsImZpbGUiOiJzcmMvQ2xpZW50LmpzIiwic291cmNlc0NvbnRlbnQiOlsiLy8gaW1wb3J0ICd4dGVuZCc7XHJcbi8vIGltcG9ydCAncG9wc2ljbGUnO1xyXG4vLyBpbXBvcnQgJ3F1ZXJ5c3RyaW5nJztcclxuLy8gaW1wb3J0ICd1cmwnO1xyXG5cclxudmFyIGhhc093blByb3BlcnR5ID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eTtcclxuXHJcbnZhciBleHRlbmQgPSBmdW5jdGlvbiBleHRlbmQoLi4uYXJnczpBcnJheTxhbnk+KTphbnkge1xyXG4gICAgdmFyIHRhcmdldCA9IHt9XHJcblxyXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmdzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgdmFyIHNvdXJjZSA9IGFyZ3NbaV1cclxuXHJcbiAgICAgICAgZm9yICh2YXIga2V5IGluIHNvdXJjZSkge1xyXG4gICAgICAgICAgICBpZiAoaGFzT3duUHJvcGVydHkuY2FsbChzb3VyY2UsIGtleSkpIHtcclxuICAgICAgICAgICAgICAgIHRhcmdldFtrZXldID0gc291cmNlW2tleV1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGFyZ2V0O1xyXG59XHJcblxyXG5cclxuXHJcbi8vdmFyIHBvcHNpY2xlICA6YW55O1xyXG4vL3ZhciBwYXJzZVF1ZXJ5IDphbnk7XHJcbi8vdmFyIHBhcnNlVXJsICA6YW55O1xyXG5cclxuLy8gdmFyIGV4dGVuZCA9IHJlcXVpcmUoJ3h0ZW5kJylcclxuLy8gdmFyIHBvcHNpY2xlID0gcmVxdWlyZSgncG9wc2ljbGUnKVxyXG4vLyB2YXIgcGFyc2VRdWVyeSA9IHJlcXVpcmUoJ3F1ZXJ5c3RyaW5nJykucGFyc2VcclxuLy8gdmFyIHBhcnNlVXJsID0gcmVxdWlyZSgndXJsJykucGFyc2VcclxuXHJcbi8vdmFyIGJ0b2EgPSB0eXBlb2YgQnVmZmVyID09PSAnZnVuY3Rpb24nID8gYnRvYUJ1ZmZlciA6IHdpbmRvdy5idG9hXHJcblxyXG4vKipcclxuICogRGVmYXVsdCBoZWFkZXJzIGZvciBleGVjdXRpbmcgT0F1dGggMi4wIGZsb3dzLlxyXG4gKlxyXG4gKiBAdHlwZSB7T2JqZWN0fVxyXG4gKi9cclxudmFyIERFRkFVTFRfSEVBREVSUyA9IHtcclxuICAnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24sIGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcsXHJcbiAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbn1cclxuXHJcbi8qKlxyXG4gKiBGb3JtYXQgZXJyb3IgcmVzcG9uc2UgdHlwZXMgdG8gcmVndWxhciBzdHJpbmdzIGZvciBkaXNwbGF5aW5nIHRvIGNsaWVudHMuXHJcbiAqXHJcbiAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMS4yLjFcclxuICpcclxuICogQHR5cGUge09iamVjdH1cclxuICovXHJcbnZhciBFUlJPUl9SRVNQT05TRVMgPSB7XHJcbiAgJ2ludmFsaWRfcmVxdWVzdCc6IFtcclxuICAgICdUaGUgcmVxdWVzdCBpcyBtaXNzaW5nIGEgcmVxdWlyZWQgcGFyYW1ldGVyLCBpbmNsdWRlcyBhbicsXHJcbiAgICAnaW52YWxpZCBwYXJhbWV0ZXIgdmFsdWUsIGluY2x1ZGVzIGEgcGFyYW1ldGVyIG1vcmUgdGhhbicsXHJcbiAgICAnb25jZSwgb3IgaXMgb3RoZXJ3aXNlIG1hbGZvcm1lZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfY2xpZW50JzogW1xyXG4gICAgJ0NsaWVudCBhdXRoZW50aWNhdGlvbiBmYWlsZWQgKGUuZy4sIHVua25vd24gY2xpZW50LCBubycsXHJcbiAgICAnY2xpZW50IGF1dGhlbnRpY2F0aW9uIGluY2x1ZGVkLCBvciB1bnN1cHBvcnRlZCcsXHJcbiAgICAnYXV0aGVudGljYXRpb24gbWV0aG9kKS4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfZ3JhbnQnOiBbXHJcbiAgICAnVGhlIHByb3ZpZGVkIGF1dGhvcml6YXRpb24gZ3JhbnQgKGUuZy4sIGF1dGhvcml6YXRpb24nLFxyXG4gICAgJ2NvZGUsIHJlc291cmNlIG93bmVyIGNyZWRlbnRpYWxzKSBvciByZWZyZXNoIHRva2VuIGlzJyxcclxuICAgICdpbnZhbGlkLCBleHBpcmVkLCByZXZva2VkLCBkb2VzIG5vdCBtYXRjaCB0aGUgcmVkaXJlY3Rpb24nLFxyXG4gICAgJ1VSSSB1c2VkIGluIHRoZSBhdXRob3JpemF0aW9uIHJlcXVlc3QsIG9yIHdhcyBpc3N1ZWQgdG8nLFxyXG4gICAgJ2Fub3RoZXIgY2xpZW50LidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5hdXRob3JpemVkX2NsaWVudCc6IFtcclxuICAgICdUaGUgY2xpZW50IGlzIG5vdCBhdXRob3JpemVkIHRvIHJlcXVlc3QgYW4gYXV0aG9yaXphdGlvbicsXHJcbiAgICAnY29kZSB1c2luZyB0aGlzIG1ldGhvZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3Vuc3VwcG9ydGVkX2dyYW50X3R5cGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gZ3JhbnQgdHlwZSBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoZScsXHJcbiAgICAnYXV0aG9yaXphdGlvbiBzZXJ2ZXIuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdhY2Nlc3NfZGVuaWVkJzogW1xyXG4gICAgJ1RoZSByZXNvdXJjZSBvd25lciBvciBhdXRob3JpemF0aW9uIHNlcnZlciBkZW5pZWQgdGhlIHJlcXVlc3QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bnN1cHBvcnRlZF9yZXNwb25zZV90eXBlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBkb2VzIG5vdCBzdXBwb3J0IG9idGFpbmluZycsXHJcbiAgICAnYW4gYXV0aG9yaXphdGlvbiBjb2RlIHVzaW5nIHRoaXMgbWV0aG9kLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9zY29wZSc6IFtcclxuICAgICdUaGUgcmVxdWVzdGVkIHNjb3BlIGlzIGludmFsaWQsIHVua25vd24sIG9yIG1hbGZvcm1lZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3NlcnZlcl9lcnJvcic6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZW5jb3VudGVyZWQgYW4gdW5leHBlY3RlZCcsXHJcbiAgICAnY29uZGl0aW9uIHRoYXQgcHJldmVudGVkIGl0IGZyb20gZnVsZmlsbGluZyB0aGUgcmVxdWVzdC4nLFxyXG4gICAgJyhUaGlzIGVycm9yIGNvZGUgaXMgbmVlZGVkIGJlY2F1c2UgYSA1MDAgSW50ZXJuYWwgU2VydmVyJyxcclxuICAgICdFcnJvciBIVFRQIHN0YXR1cyBjb2RlIGNhbm5vdCBiZSByZXR1cm5lZCB0byB0aGUgY2xpZW50JyxcclxuICAgICd2aWEgYW4gSFRUUCByZWRpcmVjdC4pJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd0ZW1wb3JhcmlseV91bmF2YWlsYWJsZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgaXMgY3VycmVudGx5IHVuYWJsZSB0byBoYW5kbGUnLFxyXG4gICAgJ3RoZSByZXF1ZXN0IGR1ZSB0byBhIHRlbXBvcmFyeSBvdmVybG9hZGluZyBvciBtYWludGVuYW5jZScsXHJcbiAgICAnb2YgdGhlIHNlcnZlci4nXHJcbiAgXS5qb2luKCcgJylcclxufVxyXG5cclxuXHJcbi8qKlxyXG4gKiBDaGVjayBpZiBwcm9wZXJ0aWVzIGV4aXN0IG9uIGFuIG9iamVjdCBhbmQgdGhyb3cgd2hlbiB0aGV5IGFyZW4ndC5cclxuICpcclxuICogQHRocm93cyB7VHlwZUVycm9yfSBJZiBhbiBleHBlY3RlZCBwcm9wZXJ0eSBpcyBtaXNzaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqXHJcbiAqIEBwYXJhbSB7QXJyYXl9ICBwcm9wc1xyXG4gKi9cclxuZnVuY3Rpb24gZXhwZWN0cyAob2JqLCBwcm9wcykge1xyXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcHJvcHMubGVuZ3RoOyBpKyspIHtcclxuICAgIHZhciBwcm9wID0gcHJvcHNbaV1cclxuXHJcbiAgICBpZiAob2JqW3Byb3BdID09IG51bGwpIHtcclxuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCInICsgcHJvcCArICdcIiB0byBleGlzdCcpXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG4vKipcclxuICogUHVsbCBhbiBhdXRoZW50aWNhdGlvbiBlcnJvciBmcm9tIHRoZSByZXNwb25zZSBkYXRhLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9IGRhdGFcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gZ2V0QXV0aEVycm9yIChkYXRhKSB7XHJcbiAgdmFyIG1lc3NhZ2UgPSBFUlJPUl9SRVNQT05TRVNbZGF0YS5lcnJvcl0gfHxcclxuICAgIGRhdGEuZXJyb3IgfHxcclxuICAgIGRhdGEuZXJyb3JfbWVzc2FnZVxyXG5cclxuICAvLyBSZXR1cm4gYW4gZXJyb3IgaW5zdGFuY2Ugd2l0aCB0aGUgbWVzc2FnZSBpZiBpdCBleGlzdHMuXHJcbiAgcmV0dXJuIG1lc3NhZ2UgJiYgbmV3IEVycm9yKG1lc3NhZ2UpXHJcbn1cclxuXHJcbi8qKlxyXG4gKiBIYW5kbGUgdGhlIGF1dGhlbnRpY2F0aW9uIHJlc3BvbnNlIG9iamVjdC5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSAgcmVzXHJcbiAqIEByZXR1cm4ge1Byb21pc2V9XHJcbiAqL1xyXG5mdW5jdGlvbiBoYW5kbGVBdXRoUmVzcG9uc2UgKHJlcykge1xyXG4gIHZhciBkYXRhID0gcmVzLmJvZHk7XHJcbiAgdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKTtcclxuXHJcbiAgLy8gSWYgdGhlIHJlc3BvbnNlIGNvbnRhaW5zIGFuIGVycm9yLCByZWplY3QgdGhlIHJlZnJlc2ggdG9rZW4uXHJcbiAgaWYgKGVycikge1xyXG4gICAgcmV0dXJuIGVycjtcclxuICB9XHJcblxyXG4gIHJldHVybiBkYXRhO1xyXG59XHJcblxyXG4vKipcclxuICogU2FuaXRpemUgdGhlIHNjb3BlcyBvcHRpb24gdG8gYmUgYSBzdHJpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSAge0FycmF5fSAgc2NvcGVzXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIHNhbml0aXplU2NvcGUgKHNjb3Blcykge1xyXG4gIHJldHVybiBBcnJheS5pc0FycmF5KHNjb3BlcykgPyBzY29wZXMuam9pbignICcpIDogc3RyaW5nKHNjb3Blcyk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDcmVhdGUgYSByZXF1ZXN0IHVyaSBiYXNlZCBvbiBhbiBvcHRpb25zIG9iamVjdCBhbmQgdG9rZW4gdHlwZS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSBvcHRpb25zXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gdG9rZW5UeXBlXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGNyZWF0ZVVyaSAob3B0aW9ucywgdG9rZW5UeXBlKSB7XHJcbiAgLy8gQ2hlY2sgdGhlIHJlcXVpcmVkIHBhcmFtZXRlcnMgYXJlIHNldC5cclxuICBleHBlY3RzKG9wdGlvbnMsIFtcclxuICAgICdjbGllbnRJZCcsXHJcbiAgICAncmVkaXJlY3RVcmknLFxyXG4gICAgJ2F1dGhvcml6YXRpb25VcmknXHJcbiAgXSk7XHJcblxyXG4gIHZhciBjbGllbnRJZCA9IGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLmNsaWVudElkKTtcclxuICB2YXIgcmVkaXJlY3RVcmkgPSBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5yZWRpcmVjdFVyaSk7XHJcbiAgdmFyIHNjb3BlcyA9IGVuY29kZVVSSUNvbXBvbmVudChzYW5pdGl6ZVNjb3BlKG9wdGlvbnMuc2NvcGVzKSk7XHJcbiAgdmFyIHVyaSA9IG9wdGlvbnMuYXV0aG9yaXphdGlvblVyaSArICc/Y2xpZW50X2lkPScgKyBjbGllbnRJZCArXHJcbiAgICAnJnJlZGlyZWN0X3VyaT0nICsgcmVkaXJlY3RVcmkgK1xyXG4gICAgJyZzY29wZT0nICsgc2NvcGVzICtcclxuICAgICcmcmVzcG9uc2VfdHlwZT0nICsgdG9rZW5UeXBlO1xyXG5cclxuICBpZiAob3B0aW9ucy5zdGF0ZSkge1xyXG4gICAgdXJpICs9ICcmc3RhdGU9JyArIGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLnN0YXRlKTtcclxuICB9XHJcblxyXG4gIHJldHVybiB1cmk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDcmVhdGUgYmFzaWMgYXV0aCBoZWFkZXIuXHJcbiAqXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gdXNlcm5hbWVcclxuICogQHBhcmFtICB7U3RyaW5nfSBwYXNzd29yZFxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBhdXRoICh1c2VybmFtZSwgcGFzc3dvcmQpIHtcclxuICByZXR1cm4gJ0Jhc2ljICcgKyBidG9hKHN0cmluZyh1c2VybmFtZSkgKyAnOicgKyBzdHJpbmcocGFzc3dvcmQpKTtcclxufVxyXG5cclxuLyoqXHJcbiAqIEVuc3VyZSBhIHZhbHVlIGlzIGEgc3RyaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHN0clxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBzdHJpbmcgKHN0cikge1xyXG4gIHJldHVybiBzdHIgPT0gbnVsbCA/ICcnIDogU3RyaW5nKHN0cik7XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgUmVxdWVzdE9wdGlvbnMge1xyXG4gICAgYm9keTogYW55O1xyXG4gICAgcXVlcnk6IGFueTtcclxuICAgIGhlYWRlcnM6IGFueTtcclxuICAgIG9wdGlvbnM6IGFueTtcclxuICAgIG1ldGhvZDogc3RyaW5nO1xyXG4gICAgdXJsOiBzdHJpbmc7XHJcbn07XHJcblxyXG4vKipcclxuICogTWVyZ2UgcmVxdWVzdCBvcHRpb25zIGZyb20gYW4gb3B0aW9ucyBvYmplY3QuXHJcbiAqL1xyXG5mdW5jdGlvbiByZXF1ZXN0T3B0aW9ucyAocmVxdWVzdE9wdGlvbnMsIG9wdGlvbnMpOiBSZXF1ZXN0T3B0aW9ucyB7XHJcblxyXG4gIHJldHVybiBleHRlbmQocmVxdWVzdE9wdGlvbnMsIHtcclxuICAgIGJvZHk6IGV4dGVuZChvcHRpb25zLmJvZHksIHJlcXVlc3RPcHRpb25zLmJvZHkpLFxyXG4gICAgcXVlcnk6IGV4dGVuZChvcHRpb25zLnF1ZXJ5LCByZXF1ZXN0T3B0aW9ucy5xdWVyeSksXHJcbiAgICBoZWFkZXJzOiBleHRlbmQob3B0aW9ucy5oZWFkZXJzLCByZXF1ZXN0T3B0aW9ucy5oZWFkZXJzKSxcclxuICAgIG9wdGlvbnM6IGV4dGVuZChvcHRpb25zLm9wdGlvbnMsIHJlcXVlc3RPcHRpb25zLm9wdGlvbnMpXHJcbiAgfSk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDb25zdHJ1Y3QgYW4gb2JqZWN0IHRoYXQgY2FuIGhhbmRsZSB0aGUgbXVsdGlwbGUgT0F1dGggMi4wIGZsb3dzLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9uc1xyXG4gKi9cclxuZXhwb3J0IGNsYXNzIENsaWVudE9BdXRoMiB7XHJcbiAgICAvLyBjb2RlIDogQ29kZUZsb3c7XHJcbiAgICAgdG9rZW4gOiBUb2tlbkZsb3c7XHJcbiAgICAvLyBvd25lciA6IE93bmVyRmxvdztcclxuICAgIC8vIGNyZWRlbnRpYWxzIDogQ3JlZGVudGlhbHNGbG93O1xyXG4gICAgLy8gand0IDogSnd0QmVhcmVyRmxvdztcclxuICAgIG9wdGlvbnMgOmFueTtcclxuICAgIFxyXG4gICAgY29uc3RydWN0b3Iob3B0aW9uczogYW55KVxyXG4gICAge1xyXG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XHJcblxyXG4gICAgICAgIC8vIHRoaXMuY29kZSA9IG5ldyBDb2RlRmxvdyh0aGlzKTtcclxuICAgICAgICB0aGlzLnRva2VuID0gbmV3IFRva2VuRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLm93bmVyID0gbmV3IE93bmVyRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLmNyZWRlbnRpYWxzID0gbmV3IENyZWRlbnRpYWxzRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLmp3dCA9IG5ldyBKd3RCZWFyZXJGbG93KHRoaXMpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgY3JlYXRlVG9rZW4oYWNjZXNzOiBzdHJpbmcsIHJlZnJlc2g6IHN0cmluZywgdHlwZTogc3RyaW5nLCBkYXRhOiBhbnkpXHJcbiAgICB7XHJcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBleHRlbmQoXHJcbiAgICAgICAgICAgIGRhdGEsXHJcbiAgICAgICAgICAgIHR5cGVvZiBhY2Nlc3MgPT09ICdzdHJpbmcnID8geyBhY2Nlc3NfdG9rZW46IGFjY2VzcyB9IDogYWNjZXNzLFxyXG4gICAgICAgICAgICB0eXBlb2YgcmVmcmVzaCA9PT0gJ3N0cmluZycgPyB7IHJlZnJlc2hfdG9rZW46IHJlZnJlc2ggfSA6IHJlZnJlc2gsXHJcbiAgICAgICAgICAgIHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJyA/IHsgdG9rZW5fdHlwZTogdHlwZSB9IDogdHlwZVxyXG4gICAgICAgICk7XHJcblxyXG4gICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4odGhpcywgb3B0aW9ucyk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBfcmVxdWVzdChyZXF1ZXN0T2JqZWN0IDogUmVxdWVzdE9wdGlvbnMpIDphbnkgXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycztcclxuICAgICAgICBmb3IobGV0IGhlYWRlciBpbiBoZWFkZXJzKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKGhlYWRlciwgaGVhZGVyc1toZWFkZXJdKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5vcGVuKHJlcXVlc3RPYmplY3QubWV0aG9kLCByZXF1ZXN0T2JqZWN0LnVybCwgZmFsc2UpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJlcXVlc3Quc2VuZChyZXF1ZXN0T2JqZWN0LmJvZHkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiByZXF1ZXN0LnJlc3BvbnNlO1xyXG4gICAgICAgIFxyXG4gICAgLy8gICByZXR1cm4gdGhpcy5yZXF1ZXN0KHJlcXVlc3RPYmplY3QpXHJcbiAgICAvLyAgICAgLnRoZW4oZnVuY3Rpb24gKHJlcykge1xyXG4gICAgLy8gICAgICAgaWYgKHJlcy5zdGF0dXMgPCAyMDAgfHwgcmVzLnN0YXR1cyA+PSAzOTkpIHtcclxuICAgIC8vICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcignSFRUUCBzdGF0dXMgJyArIHJlcy5zdGF0dXMpXHJcbiAgICAvLyAgICAgICAgIGVyci5zdGF0dXMgPSByZXMuc3RhdHVzXHJcbiAgICAvLyAgICAgICAgIGVyci5ib2R5ID0gcmVzLmJvZHlcclxuICAgIC8vICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgIC8vICAgICAgIH1cclxuXHJcbiAgICAvLyAgICAgICByZXR1cm4gcmVzXHJcbiAgICAvLyAgICAgfSlcclxuICAgIH1cclxufVxyXG5cclxuLyoqXHJcbiAqIEFsaWFzIHRoZSB0b2tlbiBjb25zdHJ1Y3Rvci5cclxuICpcclxuICogQHR5cGUge0Z1bmN0aW9ufVxyXG4gKi9cclxuLy9DbGllbnRPQXV0aDIuVG9rZW4gPSBDbGllbnRPQXV0aDJUb2tlblxyXG5cclxuXHJcbi8qKlxyXG4gKiBVc2luZyB0aGUgYnVpbHQtaW4gcmVxdWVzdCBtZXRob2QsIHdlJ2xsIGF1dG9tYXRpY2FsbHkgYXR0ZW1wdCB0byBwYXJzZVxyXG4gKiB0aGUgcmVzcG9uc2UuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gIHJlcXVlc3RPYmplY3RcclxuICogQHJldHVybiB7UHJvbWlzZX1cclxuICovXHJcblxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFNldCBgcG9wc2ljbGVgIGFzIHRoZSBkZWZhdWx0IHJlcXVlc3QgbWV0aG9kLlxyXG4vLyAgKi9cclxuLy8gQ2xpZW50T0F1dGgyLnByb3RvdHlwZS5yZXF1ZXN0ID0gcG9wc2ljbGUucmVxdWVzdFxyXG5cclxuLyoqXHJcbiAqIEdlbmVyYWwgcHVycG9zZSBjbGllbnQgdG9rZW4gZ2VuZXJhdG9yLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gY2xpZW50XHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBkYXRhXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQ2xpZW50T0F1dGgyVG9rZW5cclxueyBcclxuICAgIGNsaWVudCA6Q2xpZW50T0F1dGgyO1xyXG4gICAgZGF0YSA6YW55O1xyXG4gICAgdG9rZW5UeXBlIDpzdHJpbmc7XHJcbiAgICBhY2Nlc3NUb2tlbiA6c3RyaW5nO1xyXG4gICAgcmVmcmVzaFRva2VuIDpzdHJpbmc7XHJcbiAgICBleHBpcmVzIDpEYXRlO1xyXG4gICAgXHJcblxyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihjbGllbnQsIGRhdGEpIHtcclxuICAgICAgICB0aGlzLmNsaWVudCA9IGNsaWVudDtcclxuICAgICAgICB0aGlzLmRhdGEgPSBkYXRhO1xyXG4gICAgICAgIHRoaXMudG9rZW5UeXBlID0gZGF0YS50b2tlbl90eXBlICYmIGRhdGEudG9rZW5fdHlwZS50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICAgIHRoaXMuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbiA9IGRhdGEucmVmcmVzaF90b2tlbjtcclxuXHJcbiAgICAgICAgdGhpcy5leHBpcmVzSW4oZGF0YS5leHBpcmVzX2luKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgXHJcbiAgICBwdWJsaWMgZXhwaXJlc0luKGR1cmF0aW9uKVxyXG4gICAge1xyXG4gICAgICAgIGlmICghaXNOYU4oZHVyYXRpb24pKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzID0gbmV3IERhdGUoKTtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzLnNldFNlY29uZHModGhpcy5leHBpcmVzLmdldFNlY29uZHMoKSArIGR1cmF0aW9uKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZWxzZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzID0gdW5kZWZpbmVkO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdGhpcy5leHBpcmVzO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgc2lnbihyZXF1ZXN0T2JqZWN0KSB7XHJcbiAgICAgICAgaWYgKCF0aGlzLmFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignVW5hYmxlIHRvIHNpZ24gd2l0aG91dCBhY2Nlc3MgdG9rZW4nKVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzID0gcmVxdWVzdE9iamVjdC5oZWFkZXJzIHx8IHt9XHJcblxyXG4gICAgICAgIGlmICh0aGlzLnRva2VuVHlwZSA9PT0gJ2JlYXJlcicpIHtcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzLkF1dGhvcml6YXRpb24gPSAnQmVhcmVyICcgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIHZhciBwYXJ0cyA9IHJlcXVlc3RPYmplY3QudXJsLnNwbGl0KCcjJyk7XHJcbiAgICAgICAgICAgIHZhciB0b2tlbiA9ICdhY2Nlc3NfdG9rZW49JyArIHRoaXMuYWNjZXNzVG9rZW47XHJcbiAgICAgICAgICAgIHZhciB1cmwgPSBwYXJ0c1swXS5yZXBsYWNlKC9bPyZdYWNjZXNzX3Rva2VuPVteJiNdLywgJycpO1xyXG4gICAgICAgICAgICB2YXIgZnJhZ21lbnQgPSBwYXJ0c1sxXSA/ICcjJyArIHBhcnRzWzFdIDogJyc7XHJcblxyXG4gICAgICAgICAgICAvLyBQcmVwZW5kIHRoZSBjb3JyZWN0IHF1ZXJ5IHN0cmluZyBwYXJhbWV0ZXIgdG8gdGhlIHVybC5cclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC51cmwgPSB1cmwgKyAodXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArIHRva2VuICsgZnJhZ21lbnQ7XHJcblxyXG4gICAgICAgICAgICAvLyBBdHRlbXB0IHRvIGF2b2lkIHN0b3JpbmcgdGhlIHVybCBpbiBwcm94aWVzLCBzaW5jZSB0aGUgYWNjZXNzIHRva2VuXHJcbiAgICAgICAgICAgIC8vIGlzIGV4cG9zZWQgaW4gdGhlIHF1ZXJ5IHBhcmFtZXRlcnMuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5QcmFnbWEgPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnNbJ0NhY2hlLUNvbnRyb2wnXSA9ICduby1zdG9yZSc7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gcmVxdWVzdE9iamVjdDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHJlcXVlc3Qob3B0aW9ucykge1xyXG4gICAgICAgIGxldCByZXF1ZXN0T3B0aW9uc1Jlc3VsdCA9IHJlcXVlc3RPcHRpb25zKHRoaXMuc2lnbihvcHRpb25zKSwgdGhpcy5jbGllbnQub3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zUmVzdWx0KTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgXHJcbiAgICBwdWJsaWMgcmVmcmVzaChvcHRpb25zKTphbnkge1xyXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcclxuXHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLnJlZnJlc2hUb2tlbikge1xyXG4gICAgICAgICAgICByZXR1cm4gbmV3IEVycm9yKCdObyByZWZyZXNoIHRva2VuIHNldCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4gICAgICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbiAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICBib2R5OiB7XHJcbiAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxyXG4gICAgICAgICAgICBncmFudF90eXBlOiAncmVmcmVzaF90b2tlbidcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0sIG9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgYm9keSA9IGhhbmRsZUF1dGhSZXNwb25zZShyZXNwb25zZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgLy9UT0RPOiBUcmF0YXIgcXVhbmRvIGV4Y2VwdGlvblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXRvcm5vID0gKGZ1bmN0aW9uIChkYXRhKSB7XHJcbiAgICAgICAgICAgIHNlbGYuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICAgICAgc2VsZi5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcblxyXG4gICAgICAgICAgICBzZWxmLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHNlbGY7XHJcbiAgICAgICAgfSkoYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJldG9ybm87XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGdldCBleHBpcmVkKCkgOiBib29sZWFuXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKHRoaXMuZXhwaXJlcykge1xyXG4gICAgICAgICAgICByZXR1cm4gRGF0ZS5ub3coKSA+IHRoaXMuZXhwaXJlcy5nZXRUaW1lKClcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxufVxyXG5cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgcmVzb3VyY2Ugb3duZXIgcGFzc3dvcmQgY3JlZGVudGlhbHMgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjNcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gT3duZXJGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogTWFrZSBhIHJlcXVlc3Qgb24gYmVoYWxmIG9mIHRoZSB1c2VyIGNyZWRlbnRpYWxzIHRvIGdldCBhbiBhY2NlcyB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgdXNlcm5hbWVcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgcGFzc3dvcmRcclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIE93bmVyRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXNlcm5hbWUsIHBhc3N3b3JkLCBvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUywge1xyXG4vLyAgICAgICBBdXRob3JpemF0aW9uOiBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgICAgfSksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIHNjb3BlOiBzYW5pdGl6ZVNjb3BlKG9wdGlvbnMuc2NvcGVzKSxcclxuLy8gICAgICAgdXNlcm5hbWU6IHVzZXJuYW1lLFxyXG4vLyAgICAgICBwYXNzd29yZDogcGFzc3dvcmQsXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICdwYXNzd29yZCdcclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcblxyXG4vKipcclxuICogU3VwcG9ydCBpbXBsaWNpdCBPQXV0aCAyLjAgZ3JhbnQuXHJcbiAqXHJcbiAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMlxyXG4gKlxyXG4gKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgVG9rZW5GbG93IFxyXG57XHJcbiAgICBjbGllbnQ6IENsaWVudE9BdXRoMjtcclxuICAgIFxyXG4gICAgY29uc3RydWN0b3IoY2xpZW50KSB7XHJcbiAgICAgICAgdGhpcy5jbGllbnQgPSBjbGllbnQ7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBnZXRVcmkob3B0aW9ucz86YW55KSB7XHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICd0b2tlbicpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRUb2tlbih1cmksIHN0YXRlPywgb3B0aW9ucz8pIFxyXG4gICAge1xyXG4gICAgICAgIC8vb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgLy8gdmFyIHVybCA9IHBhcnNlVXJsKHVyaSlcclxuICAgICAgICAvLyB2YXIgZXhwZWN0ZWRVcmwgPSBwYXJzZVVybChvcHRpb25zLnJlZGlyZWN0VXJpKVxyXG5cclxuICAgICAgICAvLyBpZiAodXJsLnBhdGhuYW1lICE9PSBleHBlY3RlZFVybC5wYXRobmFtZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyAvLyBJZiBubyBxdWVyeSBzdHJpbmcgb3IgZnJhZ21lbnQgZXhpc3RzLCB3ZSB3b24ndCBiZSBhYmxlIHRvIHBhcnNlXHJcbiAgICAgICAgLy8gLy8gYW55IHVzZWZ1bCBpbmZvcm1hdGlvbiBmcm9tIHRoZSB1cmkuXHJcbiAgICAgICAgLy8gaWYgKCF1cmwuaGFzaCAmJiAhdXJsLnNlYXJjaCkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignVW5hYmxlIHRvIHByb2Nlc3MgdXJpOiAnICsgdXJpKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIEV4dHJhY3QgZGF0YSBmcm9tIGJvdGggdGhlIGZyYWdtZW50IGFuZCBxdWVyeSBzdHJpbmcuIFRoZSBmcmFnbWVudCBpcyBtb3N0XHJcbiAgICAgICAgLy8gaW1wb3J0YW50LCBidXQgdGhlIHF1ZXJ5IHN0cmluZyBpcyBhbHNvIHVzZWQgYmVjYXVzZSBzb21lIE9BdXRoIDIuMFxyXG4gICAgICAgIC8vIGltcGxlbWVudGF0aW9ucyAoSW5zdGFncmFtKSBoYXZlIGEgYnVnIHdoZXJlIHN0YXRlIGlzIHBhc3NlZCB2aWEgcXVlcnkuXHJcbiAgICAgICAgLy8gdmFyIGRhdGEgPSBleHRlbmQoXHJcbiAgICAgICAgLy8gICAgIHVybC5xdWVyeSA/IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KSA6IHt9LFxyXG4gICAgICAgIC8vICAgICB1cmwuaGFzaCA/IHBhcnNlUXVlcnkodXJsLmhhc2guc3Vic3RyKDEpKSA6IHt9XHJcbiAgICAgICAgLy8gKVxyXG5cclxuICAgICAgICAvLyB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIGlmIHRoZSBxdWVyeSBzdHJpbmcgd2FzIHBvcHVsYXRlZCB3aXRoIGEga25vd24gZXJyb3IuXHJcbiAgICAgICAgLy8gaWYgKGVycikge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gQ2hlY2sgd2hldGhlciB0aGUgc3RhdGUgbWF0Y2hlcy5cclxuICAgICAgICAvLyBpZiAoc3RhdGUgIT0gbnVsbCAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignSW52YWxpZCBzdGF0ZTogJyArIGRhdGEuc3RhdGUpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgZnVuY3Rpb24gUGFyc2VhclVybCh1cmw6IHN0cmluZylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKHVybC5pbmRleE9mKCcjJykgIT09IC0xKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdXJsLnN1YnN0cih1cmwuaW5kZXhPZignIycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJz8nKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IHVybFBhcnNlYWRhID0gUGFyc2VhclVybCh1cmkpO1xyXG5cclxuICAgICAgICBsZXQgZGF0YSA9IHVybFBhcnNlYWRhO1xyXG5cclxuICAgICAgICAvLyBJbml0YWxpemUgYSBuZXcgdG9rZW4gYW5kIHJldHVybi5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMuY2xpZW50LCBkYXRhKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcbiAgICBcclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgY2xpZW50IGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC40XHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIENyZWRlbnRpYWxzRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFJlcXVlc3QgYW4gYWNjZXNzIHRva2VuIHVzaW5nIHRoZSBjbGllbnQgY3JlZGVudGlhbHMuXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gQ3JlZGVudGlhbHNGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbi8vICAgICAnY2xpZW50SWQnLFxyXG4vLyAgICAgJ2NsaWVudFNlY3JldCcsXHJcbi8vICAgICAnYWNjZXNzVG9rZW5VcmknXHJcbi8vICAgXSlcclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUywge1xyXG4vLyAgICAgICBBdXRob3JpemF0aW9uOiBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgICAgfSksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIHNjb3BlOiBzYW5pdGl6ZVNjb3BlKG9wdGlvbnMuc2NvcGVzKSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ2NsaWVudF9jcmVkZW50aWFscydcclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBhdXRob3JpemF0aW9uIGNvZGUgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjFcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gQ29kZUZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBHZW5lcmF0ZSB0aGUgdXJpIGZvciBkb2luZyB0aGUgZmlyc3QgcmVkaXJlY3QuXHJcbi8vICAqXHJcbi8vICAqIEByZXR1cm4ge1N0cmluZ31cclxuLy8gICovXHJcbi8vIENvZGVGbG93LnByb3RvdHlwZS5nZXRVcmkgPSBmdW5jdGlvbiAob3B0aW9ucykge1xyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgcmV0dXJuIGNyZWF0ZVVyaShvcHRpb25zLCAnY29kZScpXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBHZXQgdGhlIGNvZGUgdG9rZW4gZnJvbSB0aGUgcmVkaXJlY3RlZCB1cmkgYW5kIG1ha2UgYW5vdGhlciByZXF1ZXN0IGZvclxyXG4vLyAgKiB0aGUgdXNlciBhY2Nlc3MgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVyaVxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICBbc3RhdGVdXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gQ29kZUZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVyaSwgc3RhdGUsIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdjbGllbnRJZCcsXHJcbi8vICAgICAnY2xpZW50U2VjcmV0JyxcclxuLy8gICAgICdyZWRpcmVjdFVyaScsXHJcbi8vICAgICAnYWNjZXNzVG9rZW5VcmknXHJcbi8vICAgXSlcclxuXHJcbi8vICAgdmFyIHVybCA9IHBhcnNlVXJsKHVyaSlcclxuLy8gICB2YXIgZXhwZWN0ZWRVcmwgPSBwYXJzZVVybChvcHRpb25zLnJlZGlyZWN0VXJpKVxyXG5cclxuLy8gICBpZiAodXJsLnBhdGhuYW1lICE9PSBleHBlY3RlZFVybC5wYXRobmFtZSkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1Nob3VsZCBtYXRjaCByZWRpcmVjdCB1cmk6ICcgKyB1cmkpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgaWYgKCF1cmwuc2VhcmNoKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignVW5hYmxlIHRvIHByb2Nlc3MgdXJpOiAnICsgdXJpKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIHZhciBkYXRhID0gcGFyc2VRdWVyeSh1cmwucXVlcnkpXHJcbi8vICAgdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKVxyXG5cclxuLy8gICBpZiAoZXJyKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgaWYgKHN0YXRlICYmIGRhdGEuc3RhdGUgIT09IHN0YXRlKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignSW52YWxpZCBzdGF0ZTonICsgZGF0YS5zdGF0ZSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICAvLyBDaGVjayB3aGV0aGVyIHRoZSByZXNwb25zZSBjb2RlIGlzIHNldC5cclxuLy8gICBpZiAoIWRhdGEuY29kZSkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ01pc3NpbmcgY29kZSwgdW5hYmxlIHRvIHJlcXVlc3QgdG9rZW4nKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMpLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBjb2RlOiBkYXRhLmNvZGUsXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICdhdXRob3JpemF0aW9uX2NvZGUnLFxyXG4vLyAgICAgICByZWRpcmVjdF91cmk6IG9wdGlvbnMucmVkaXJlY3RVcmksXHJcbi8vICAgICAgIGNsaWVudF9pZDogb3B0aW9ucy5jbGllbnRJZCxcclxuLy8gICAgICAgY2xpZW50X3NlY3JldDogb3B0aW9ucy5jbGllbnRTZWNyZXRcclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBKU09OIFdlYiBUb2tlbiAoSldUKSBCZWFyZXIgVG9rZW4gT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9kcmFmdC1pZXRmLW9hdXRoLWp3dC1iZWFyZXItMTIjc2VjdGlvbi0yLjFcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gSnd0QmVhcmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFJlcXVlc3QgYW4gYWNjZXNzIHRva2VuIHVzaW5nIGEgSldUIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtzdHJpbmd9IHRva2VuIEEgSldUIHRva2VuLlxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIEp3dEJlYXJlckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHRva2VuLCBvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbi8vICAgICAnYWNjZXNzVG9rZW5VcmknXHJcbi8vICAgXSlcclxuXHJcbi8vICAgdmFyIGhlYWRlcnMgPSBleHRlbmQoREVGQVVMVF9IRUFERVJTKVxyXG5cclxuLy8gICAvLyBBdXRoZW50aWNhdGlvbiBvZiB0aGUgY2xpZW50IGlzIG9wdGlvbmFsLCBhcyBkZXNjcmliZWQgaW5cclxuLy8gICAvLyBTZWN0aW9uIDMuMi4xIG9mIE9BdXRoIDIuMCBbUkZDNjc0OV1cclxuLy8gICBpZiAob3B0aW9ucy5jbGllbnRJZCkge1xyXG4vLyAgICAgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICB9XHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGhlYWRlcnMsXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIHNjb3BlOiBzYW5pdGl6ZVNjb3BlKG9wdGlvbnMuc2NvcGVzKSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ3VybjppZXRmOnBhcmFtczpvYXV0aDpncmFudC10eXBlOmp3dC1iZWFyZXInLFxyXG4vLyAgICAgICBhc3NlcnRpb246IHRva2VuXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG4iXX0=
