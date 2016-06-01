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
                            url.substr(url.indexOf('#'), url.length).replace('?', '').replace('#', '').split('&').reduce(function (s, c) { var t = c.split('='); s[t[0]] = t[1]; return s; }, {});
                        }
                        else {
                            url.substr(url.indexOf('?'), url.length).replace('?', '').replace('#', '').split('&').reduce(function (s, c) { var t = c.split('='); s[t[0]] = t[1]; return s; }, {});
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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cyIsInNvdXJjZXNDb250ZW50IjpbIi8vIGltcG9ydCAneHRlbmQnO1xyXG4vLyBpbXBvcnQgJ3BvcHNpY2xlJztcclxuLy8gaW1wb3J0ICdxdWVyeXN0cmluZyc7XHJcbi8vIGltcG9ydCAndXJsJztcclxuXHJcbnZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XHJcblxyXG52YXIgZXh0ZW5kID0gZnVuY3Rpb24gZXh0ZW5kKC4uLmFyZ3M6QXJyYXk8YW55Pik6YW55IHtcclxuICAgIHZhciB0YXJnZXQgPSB7fVxyXG5cclxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgIHZhciBzb3VyY2UgPSBhcmdzW2ldXHJcblxyXG4gICAgICAgIGZvciAodmFyIGtleSBpbiBzb3VyY2UpIHtcclxuICAgICAgICAgICAgaWYgKGhhc093blByb3BlcnR5LmNhbGwoc291cmNlLCBrZXkpKSB7XHJcbiAgICAgICAgICAgICAgICB0YXJnZXRba2V5XSA9IHNvdXJjZVtrZXldXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRhcmdldDtcclxufVxyXG5cclxuXHJcblxyXG4vL3ZhciBwb3BzaWNsZSAgOmFueTtcclxuLy92YXIgcGFyc2VRdWVyeSA6YW55O1xyXG4vL3ZhciBwYXJzZVVybCAgOmFueTtcclxuXHJcbi8vIHZhciBleHRlbmQgPSByZXF1aXJlKCd4dGVuZCcpXHJcbi8vIHZhciBwb3BzaWNsZSA9IHJlcXVpcmUoJ3BvcHNpY2xlJylcclxuLy8gdmFyIHBhcnNlUXVlcnkgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpLnBhcnNlXHJcbi8vIHZhciBwYXJzZVVybCA9IHJlcXVpcmUoJ3VybCcpLnBhcnNlXHJcblxyXG4vL3ZhciBidG9hID0gdHlwZW9mIEJ1ZmZlciA9PT0gJ2Z1bmN0aW9uJyA/IGJ0b2FCdWZmZXIgOiB3aW5kb3cuYnRvYVxyXG5cclxuLyoqXHJcbiAqIERlZmF1bHQgaGVhZGVycyBmb3IgZXhlY3V0aW5nIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHR5cGUge09iamVjdH1cclxuICovXHJcbnZhciBERUZBVUxUX0hFQURFUlMgPSB7XHJcbiAgJ0FjY2VwdCc6ICdhcHBsaWNhdGlvbi9qc29uLCBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnLFxyXG4gICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG59XHJcblxyXG4vKipcclxuICogRm9ybWF0IGVycm9yIHJlc3BvbnNlIHR5cGVzIHRvIHJlZ3VsYXIgc3RyaW5ncyBmb3IgZGlzcGxheWluZyB0byBjbGllbnRzLlxyXG4gKlxyXG4gKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjEuMi4xXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgRVJST1JfUkVTUE9OU0VTID0ge1xyXG4gICdpbnZhbGlkX3JlcXVlc3QnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3QgaXMgbWlzc2luZyBhIHJlcXVpcmVkIHBhcmFtZXRlciwgaW5jbHVkZXMgYW4nLFxyXG4gICAgJ2ludmFsaWQgcGFyYW1ldGVyIHZhbHVlLCBpbmNsdWRlcyBhIHBhcmFtZXRlciBtb3JlIHRoYW4nLFxyXG4gICAgJ29uY2UsIG9yIGlzIG90aGVyd2lzZSBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2NsaWVudCc6IFtcclxuICAgICdDbGllbnQgYXV0aGVudGljYXRpb24gZmFpbGVkIChlLmcuLCB1bmtub3duIGNsaWVudCwgbm8nLFxyXG4gICAgJ2NsaWVudCBhdXRoZW50aWNhdGlvbiBpbmNsdWRlZCwgb3IgdW5zdXBwb3J0ZWQnLFxyXG4gICAgJ2F1dGhlbnRpY2F0aW9uIG1ldGhvZCkuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2dyYW50JzogW1xyXG4gICAgJ1RoZSBwcm92aWRlZCBhdXRob3JpemF0aW9uIGdyYW50IChlLmcuLCBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlLCByZXNvdXJjZSBvd25lciBjcmVkZW50aWFscykgb3IgcmVmcmVzaCB0b2tlbiBpcycsXHJcbiAgICAnaW52YWxpZCwgZXhwaXJlZCwgcmV2b2tlZCwgZG9lcyBub3QgbWF0Y2ggdGhlIHJlZGlyZWN0aW9uJyxcclxuICAgICdVUkkgdXNlZCBpbiB0aGUgYXV0aG9yaXphdGlvbiByZXF1ZXN0LCBvciB3YXMgaXNzdWVkIHRvJyxcclxuICAgICdhbm90aGVyIGNsaWVudC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3VuYXV0aG9yaXplZF9jbGllbnQnOiBbXHJcbiAgICAnVGhlIGNsaWVudCBpcyBub3QgYXV0aG9yaXplZCB0byByZXF1ZXN0IGFuIGF1dGhvcml6YXRpb24nLFxyXG4gICAgJ2NvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bnN1cHBvcnRlZF9ncmFudF90eXBlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIGdyYW50IHR5cGUgaXMgbm90IHN1cHBvcnRlZCBieSB0aGUnLFxyXG4gICAgJ2F1dGhvcml6YXRpb24gc2VydmVyLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnYWNjZXNzX2RlbmllZCc6IFtcclxuICAgICdUaGUgcmVzb3VyY2Ugb3duZXIgb3IgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZGVuaWVkIHRoZSByZXF1ZXN0LidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfcmVzcG9uc2VfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZG9lcyBub3Qgc3VwcG9ydCBvYnRhaW5pbmcnLFxyXG4gICAgJ2FuIGF1dGhvcml6YXRpb24gY29kZSB1c2luZyB0aGlzIG1ldGhvZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfc2NvcGUnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3RlZCBzY29wZSBpcyBpbnZhbGlkLCB1bmtub3duLCBvciBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdzZXJ2ZXJfZXJyb3InOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGVuY291bnRlcmVkIGFuIHVuZXhwZWN0ZWQnLFxyXG4gICAgJ2NvbmRpdGlvbiB0aGF0IHByZXZlbnRlZCBpdCBmcm9tIGZ1bGZpbGxpbmcgdGhlIHJlcXVlc3QuJyxcclxuICAgICcoVGhpcyBlcnJvciBjb2RlIGlzIG5lZWRlZCBiZWNhdXNlIGEgNTAwIEludGVybmFsIFNlcnZlcicsXHJcbiAgICAnRXJyb3IgSFRUUCBzdGF0dXMgY29kZSBjYW5ub3QgYmUgcmV0dXJuZWQgdG8gdGhlIGNsaWVudCcsXHJcbiAgICAndmlhIGFuIEhUVFAgcmVkaXJlY3QuKSdcclxuICBdLmpvaW4oJyAnKSxcclxuICAndGVtcG9yYXJpbHlfdW5hdmFpbGFibGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGlzIGN1cnJlbnRseSB1bmFibGUgdG8gaGFuZGxlJyxcclxuICAgICd0aGUgcmVxdWVzdCBkdWUgdG8gYSB0ZW1wb3Jhcnkgb3ZlcmxvYWRpbmcgb3IgbWFpbnRlbmFuY2UnLFxyXG4gICAgJ29mIHRoZSBzZXJ2ZXIuJ1xyXG4gIF0uam9pbignICcpXHJcbn1cclxuXHJcblxyXG4vKipcclxuICogQ2hlY2sgaWYgcHJvcGVydGllcyBleGlzdCBvbiBhbiBvYmplY3QgYW5kIHRocm93IHdoZW4gdGhleSBhcmVuJ3QuXHJcbiAqXHJcbiAqIEB0aHJvd3Mge1R5cGVFcnJvcn0gSWYgYW4gZXhwZWN0ZWQgcHJvcGVydHkgaXMgbWlzc2luZy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9ialxyXG4gKiBAcGFyYW0ge0FycmF5fSAgcHJvcHNcclxuICovXHJcbmZ1bmN0aW9uIGV4cGVjdHMgKG9iaiwgcHJvcHMpIHtcclxuICBmb3IgKHZhciBpID0gMDsgaSA8IHByb3BzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICB2YXIgcHJvcCA9IHByb3BzW2ldXHJcblxyXG4gICAgaWYgKG9ialtwcm9wXSA9PSBudWxsKSB7XHJcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiJyArIHByb3AgKyAnXCIgdG8gZXhpc3QnKVxyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuLyoqXHJcbiAqIFB1bGwgYW4gYXV0aGVudGljYXRpb24gZXJyb3IgZnJvbSB0aGUgcmVzcG9uc2UgZGF0YS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSBkYXRhXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGdldEF1dGhFcnJvciAoZGF0YSkge1xyXG4gIHZhciBtZXNzYWdlID0gRVJST1JfUkVTUE9OU0VTW2RhdGEuZXJyb3JdIHx8XHJcbiAgICBkYXRhLmVycm9yIHx8XHJcbiAgICBkYXRhLmVycm9yX21lc3NhZ2VcclxuXHJcbiAgLy8gUmV0dXJuIGFuIGVycm9yIGluc3RhbmNlIHdpdGggdGhlIG1lc3NhZ2UgaWYgaXQgZXhpc3RzLlxyXG4gIHJldHVybiBtZXNzYWdlICYmIG5ldyBFcnJvcihtZXNzYWdlKVxyXG59XHJcblxyXG4vKipcclxuICogSGFuZGxlIHRoZSBhdXRoZW50aWNhdGlvbiByZXNwb25zZSBvYmplY3QuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gIHJlc1xyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuZnVuY3Rpb24gaGFuZGxlQXV0aFJlc3BvbnNlIChyZXMpIHtcclxuICB2YXIgZGF0YSA9IHJlcy5ib2R5O1xyXG4gIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSk7XHJcblxyXG4gIC8vIElmIHRoZSByZXNwb25zZSBjb250YWlucyBhbiBlcnJvciwgcmVqZWN0IHRoZSByZWZyZXNoIHRva2VuLlxyXG4gIGlmIChlcnIpIHtcclxuICAgIHJldHVybiBlcnI7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZGF0YTtcclxufVxyXG5cclxuLyoqXHJcbiAqIFNhbml0aXplIHRoZSBzY29wZXMgb3B0aW9uIHRvIGJlIGEgc3RyaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtBcnJheX0gIHNjb3Blc1xyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBzYW5pdGl6ZVNjb3BlIChzY29wZXMpIHtcclxuICByZXR1cm4gQXJyYXkuaXNBcnJheShzY29wZXMpID8gc2NvcGVzLmpvaW4oJyAnKSA6IHN0cmluZyhzY29wZXMpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGEgcmVxdWVzdCB1cmkgYmFzZWQgb24gYW4gb3B0aW9ucyBvYmplY3QgYW5kIHRva2VuIHR5cGUuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gb3B0aW9uc1xyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHRva2VuVHlwZVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBjcmVhdGVVcmkgKG9wdGlvbnMsIHRva2VuVHlwZSkge1xyXG4gIC8vIENoZWNrIHRoZSByZXF1aXJlZCBwYXJhbWV0ZXJzIGFyZSBzZXQuXHJcbiAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbiAgICAnY2xpZW50SWQnLFxyXG4gICAgJ3JlZGlyZWN0VXJpJyxcclxuICAgICdhdXRob3JpemF0aW9uVXJpJ1xyXG4gIF0pO1xyXG5cclxuICB2YXIgY2xpZW50SWQgPSBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5jbGllbnRJZCk7XHJcbiAgdmFyIHJlZGlyZWN0VXJpID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMucmVkaXJlY3RVcmkpO1xyXG4gIHZhciBzY29wZXMgPSBlbmNvZGVVUklDb21wb25lbnQoc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcykpO1xyXG4gIHZhciB1cmkgPSBvcHRpb25zLmF1dGhvcml6YXRpb25VcmkgKyAnP2NsaWVudF9pZD0nICsgY2xpZW50SWQgK1xyXG4gICAgJyZyZWRpcmVjdF91cmk9JyArIHJlZGlyZWN0VXJpICtcclxuICAgICcmc2NvcGU9JyArIHNjb3BlcyArXHJcbiAgICAnJnJlc3BvbnNlX3R5cGU9JyArIHRva2VuVHlwZTtcclxuXHJcbiAgaWYgKG9wdGlvbnMuc3RhdGUpIHtcclxuICAgIHVyaSArPSAnJnN0YXRlPScgKyBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5zdGF0ZSk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gdXJpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGJhc2ljIGF1dGggaGVhZGVyLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHVzZXJuYW1lXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gcGFzc3dvcmRcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gYXV0aCAodXNlcm5hbWUsIHBhc3N3b3JkKSB7XHJcbiAgcmV0dXJuICdCYXNpYyAnICsgYnRvYShzdHJpbmcodXNlcm5hbWUpICsgJzonICsgc3RyaW5nKHBhc3N3b3JkKSk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBFbnN1cmUgYSB2YWx1ZSBpcyBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSBzdHJcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc3RyaW5nIChzdHIpIHtcclxuICByZXR1cm4gc3RyID09IG51bGwgPyAnJyA6IFN0cmluZyhzdHIpO1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFJlcXVlc3RPcHRpb25zIHtcclxuICAgIGJvZHk6IGFueTtcclxuICAgIHF1ZXJ5OiBhbnk7XHJcbiAgICBoZWFkZXJzOiBhbnk7XHJcbiAgICBvcHRpb25zOiBhbnk7XHJcbiAgICBtZXRob2Q6IHN0cmluZztcclxuICAgIHVybDogc3RyaW5nO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIE1lcmdlIHJlcXVlc3Qgb3B0aW9ucyBmcm9tIGFuIG9wdGlvbnMgb2JqZWN0LlxyXG4gKi9cclxuZnVuY3Rpb24gcmVxdWVzdE9wdGlvbnMgKHJlcXVlc3RPcHRpb25zLCBvcHRpb25zKTogUmVxdWVzdE9wdGlvbnMge1xyXG5cclxuICByZXR1cm4gZXh0ZW5kKHJlcXVlc3RPcHRpb25zLCB7XHJcbiAgICBib2R5OiBleHRlbmQob3B0aW9ucy5ib2R5LCByZXF1ZXN0T3B0aW9ucy5ib2R5KSxcclxuICAgIHF1ZXJ5OiBleHRlbmQob3B0aW9ucy5xdWVyeSwgcmVxdWVzdE9wdGlvbnMucXVlcnkpLFxyXG4gICAgaGVhZGVyczogZXh0ZW5kKG9wdGlvbnMuaGVhZGVycywgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXHJcbiAgICBvcHRpb25zOiBleHRlbmQob3B0aW9ucy5vcHRpb25zLCByZXF1ZXN0T3B0aW9ucy5vcHRpb25zKVxyXG4gIH0pO1xyXG59XHJcblxyXG4vKipcclxuICogQ29uc3RydWN0IGFuIG9iamVjdCB0aGF0IGNhbiBoYW5kbGUgdGhlIG11bHRpcGxlIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDIge1xyXG4gICAgLy8gY29kZSA6IENvZGVGbG93O1xyXG4gICAgIHRva2VuIDogVG9rZW5GbG93O1xyXG4gICAgLy8gb3duZXIgOiBPd25lckZsb3c7XHJcbiAgICAvLyBjcmVkZW50aWFscyA6IENyZWRlbnRpYWxzRmxvdztcclxuICAgIC8vIGp3dCA6IEp3dEJlYXJlckZsb3c7XHJcbiAgICBvcHRpb25zIDphbnk7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKG9wdGlvbnM6IGFueSlcclxuICAgIHtcclxuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xyXG5cclxuICAgICAgICAvLyB0aGlzLmNvZGUgPSBuZXcgQ29kZUZsb3codGhpcyk7XHJcbiAgICAgICAgdGhpcy50b2tlbiA9IG5ldyBUb2tlbkZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5vd25lciA9IG5ldyBPd25lckZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5jcmVkZW50aWFscyA9IG5ldyBDcmVkZW50aWFsc0Zsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5qd3QgPSBuZXcgSnd0QmVhcmVyRmxvdyh0aGlzKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIGNyZWF0ZVRva2VuKGFjY2Vzczogc3RyaW5nLCByZWZyZXNoOiBzdHJpbmcsIHR5cGU6IHN0cmluZywgZGF0YTogYW55KVxyXG4gICAge1xyXG4gICAgICAgIHZhciBvcHRpb25zID0gZXh0ZW5kKFxyXG4gICAgICAgICAgICBkYXRhLFxyXG4gICAgICAgICAgICB0eXBlb2YgYWNjZXNzID09PSAnc3RyaW5nJyA/IHsgYWNjZXNzX3Rva2VuOiBhY2Nlc3MgfSA6IGFjY2VzcyxcclxuICAgICAgICAgICAgdHlwZW9mIHJlZnJlc2ggPT09ICdzdHJpbmcnID8geyByZWZyZXNoX3Rva2VuOiByZWZyZXNoIH0gOiByZWZyZXNoLFxyXG4gICAgICAgICAgICB0eXBlb2YgdHlwZSA9PT0gJ3N0cmluZycgPyB7IHRva2VuX3R5cGU6IHR5cGUgfSA6IHR5cGVcclxuICAgICAgICApO1xyXG5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMsIG9wdGlvbnMpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgX3JlcXVlc3QocmVxdWVzdE9iamVjdCA6IFJlcXVlc3RPcHRpb25zKSA6YW55IFxyXG4gICAge1xyXG4gICAgICAgIGxldCByZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGhlYWRlcnMgPSByZXF1ZXN0T2JqZWN0LmhlYWRlcnM7XHJcbiAgICAgICAgZm9yKGxldCBoZWFkZXIgaW4gaGVhZGVycylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihoZWFkZXIsIGhlYWRlcnNbaGVhZGVyXSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIHJlcXVlc3Qub3BlbihyZXF1ZXN0T2JqZWN0Lm1ldGhvZCwgcmVxdWVzdE9iamVjdC51cmwsIGZhbHNlKTtcclxuICAgICAgICBcclxuICAgICAgICByZXF1ZXN0LnNlbmQocmVxdWVzdE9iamVjdC5ib2R5KTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gcmVxdWVzdC5yZXNwb25zZTtcclxuICAgICAgICBcclxuICAgIC8vICAgcmV0dXJuIHRoaXMucmVxdWVzdChyZXF1ZXN0T2JqZWN0KVxyXG4gICAgLy8gICAgIC50aGVuKGZ1bmN0aW9uIChyZXMpIHtcclxuICAgIC8vICAgICAgIGlmIChyZXMuc3RhdHVzIDwgMjAwIHx8IHJlcy5zdGF0dXMgPj0gMzk5KSB7XHJcbiAgICAvLyAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoJ0hUVFAgc3RhdHVzICcgKyByZXMuc3RhdHVzKVxyXG4gICAgLy8gICAgICAgICBlcnIuc3RhdHVzID0gcmVzLnN0YXR1c1xyXG4gICAgLy8gICAgICAgICBlcnIuYm9keSA9IHJlcy5ib2R5XHJcbiAgICAvLyAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbiAgICAvLyAgICAgICB9XHJcblxyXG4gICAgLy8gICAgICAgcmV0dXJuIHJlc1xyXG4gICAgLy8gICAgIH0pXHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBBbGlhcyB0aGUgdG9rZW4gY29uc3RydWN0b3IuXHJcbiAqXHJcbiAqIEB0eXBlIHtGdW5jdGlvbn1cclxuICovXHJcbi8vQ2xpZW50T0F1dGgyLlRva2VuID0gQ2xpZW50T0F1dGgyVG9rZW5cclxuXHJcblxyXG4vKipcclxuICogVXNpbmcgdGhlIGJ1aWx0LWluIHJlcXVlc3QgbWV0aG9kLCB3ZSdsbCBhdXRvbWF0aWNhbGx5IGF0dGVtcHQgdG8gcGFyc2VcclxuICogdGhlIHJlc3BvbnNlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXF1ZXN0T2JqZWN0XHJcbiAqIEByZXR1cm4ge1Byb21pc2V9XHJcbiAqL1xyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTZXQgYHBvcHNpY2xlYCBhcyB0aGUgZGVmYXVsdCByZXF1ZXN0IG1ldGhvZC5cclxuLy8gICovXHJcbi8vIENsaWVudE9BdXRoMi5wcm90b3R5cGUucmVxdWVzdCA9IHBvcHNpY2xlLnJlcXVlc3RcclxuXHJcbi8qKlxyXG4gKiBHZW5lcmFsIHB1cnBvc2UgY2xpZW50IHRva2VuIGdlbmVyYXRvci5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IGNsaWVudFxyXG4gKiBAcGFyYW0ge09iamVjdH0gZGF0YVxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIENsaWVudE9BdXRoMlRva2VuXHJcbnsgXHJcbiAgICBjbGllbnQgOkNsaWVudE9BdXRoMjtcclxuICAgIGRhdGEgOmFueTtcclxuICAgIHRva2VuVHlwZSA6c3RyaW5nO1xyXG4gICAgYWNjZXNzVG9rZW4gOnN0cmluZztcclxuICAgIHJlZnJlc2hUb2tlbiA6c3RyaW5nO1xyXG4gICAgZXhwaXJlcyA6RGF0ZTtcclxuICAgIFxyXG5cclxuICAgIFxyXG4gICAgY29uc3RydWN0b3IoY2xpZW50LCBkYXRhKSB7XHJcbiAgICAgICAgdGhpcy5jbGllbnQgPSBjbGllbnQ7XHJcbiAgICAgICAgdGhpcy5kYXRhID0gZGF0YTtcclxuICAgICAgICB0aGlzLnRva2VuVHlwZSA9IGRhdGEudG9rZW5fdHlwZSAmJiBkYXRhLnRva2VuX3R5cGUudG9Mb3dlckNhc2UoKTtcclxuICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuID0gZGF0YS5hY2Nlc3NfdG9rZW47XHJcbiAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcblxyXG4gICAgICAgIHRoaXMuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIGV4cGlyZXNJbihkdXJhdGlvbilcclxuICAgIHtcclxuICAgICAgICBpZiAoIWlzTmFOKGR1cmF0aW9uKSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcy5zZXRTZWNvbmRzKHRoaXMuZXhwaXJlcy5nZXRTZWNvbmRzKCkgKyBkdXJhdGlvbik7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2VcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IHVuZGVmaW5lZDtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZXhwaXJlcztcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHNpZ24ocmVxdWVzdE9iamVjdCkge1xyXG4gICAgICAgIGlmICghdGhpcy5hY2Nlc3NUb2tlbikge1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1VuYWJsZSB0byBzaWduIHdpdGhvdXQgYWNjZXNzIHRva2VuJylcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycyB8fCB7fVxyXG5cclxuICAgICAgICBpZiAodGhpcy50b2tlblR5cGUgPT09ICdiZWFyZXInKSB7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5BdXRob3JpemF0aW9uID0gJ0JlYXJlciAnICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB2YXIgcGFydHMgPSByZXF1ZXN0T2JqZWN0LnVybC5zcGxpdCgnIycpO1xyXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSAnYWNjZXNzX3Rva2VuPScgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgICAgICB2YXIgdXJsID0gcGFydHNbMF0ucmVwbGFjZSgvWz8mXWFjY2Vzc190b2tlbj1bXiYjXS8sICcnKTtcclxuICAgICAgICAgICAgdmFyIGZyYWdtZW50ID0gcGFydHNbMV0gPyAnIycgKyBwYXJ0c1sxXSA6ICcnO1xyXG5cclxuICAgICAgICAgICAgLy8gUHJlcGVuZCB0aGUgY29ycmVjdCBxdWVyeSBzdHJpbmcgcGFyYW1ldGVyIHRvIHRoZSB1cmwuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QudXJsID0gdXJsICsgKHVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgKyB0b2tlbiArIGZyYWdtZW50O1xyXG5cclxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBhdm9pZCBzdG9yaW5nIHRoZSB1cmwgaW4gcHJveGllcywgc2luY2UgdGhlIGFjY2VzcyB0b2tlblxyXG4gICAgICAgICAgICAvLyBpcyBleHBvc2VkIGluIHRoZSBxdWVyeSBwYXJhbWV0ZXJzLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuUHJhZ21hID0gJ25vLXN0b3JlJztcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzWydDYWNoZS1Db250cm9sJ10gPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3RPYmplY3Q7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyByZXF1ZXN0KG9wdGlvbnMpIHtcclxuICAgICAgICBsZXQgcmVxdWVzdE9wdGlvbnNSZXN1bHQgPSByZXF1ZXN0T3B0aW9ucyh0aGlzLnNpZ24ob3B0aW9ucyksIHRoaXMuY2xpZW50Lm9wdGlvbnMpO1xyXG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9uc1Jlc3VsdCk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIHJlZnJlc2gob3B0aW9ucyk6YW55IHtcclxuICAgICAgICB2YXIgc2VsZiA9IHRoaXM7XHJcblxyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5yZWZyZXNoVG9rZW4pIHtcclxuICAgICAgICAgICAgcmV0dXJuIG5ldyBFcnJvcignTm8gcmVmcmVzaCB0b2tlbiBzZXQnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXNwb25zZSA9IHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuICAgICAgICAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4gICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcclxuICAgICAgICAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUywge1xyXG4gICAgICAgICAgICBBdXRob3JpemF0aW9uOiBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4gICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgYm9keToge1xyXG4gICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcclxuICAgICAgICAgICAgZ3JhbnRfdHlwZTogJ3JlZnJlc2hfdG9rZW4nXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9LCBvcHRpb25zKSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGJvZHkgPSBoYW5kbGVBdXRoUmVzcG9uc2UocmVzcG9uc2UpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIC8vVE9ETzogVHJhdGFyIHF1YW5kbyBleGNlcHRpb25cclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmV0b3JubyA9IChmdW5jdGlvbiAoZGF0YSkge1xyXG4gICAgICAgICAgICBzZWxmLmFjY2Vzc1Rva2VuID0gZGF0YS5hY2Nlc3NfdG9rZW47XHJcbiAgICAgICAgICAgIHNlbGYucmVmcmVzaFRva2VuID0gZGF0YS5yZWZyZXNoX3Rva2VuO1xyXG5cclxuICAgICAgICAgICAgc2VsZi5leHBpcmVzSW4oZGF0YS5leHBpcmVzX2luKTtcclxuXHJcbiAgICAgICAgICAgIHJldHVybiBzZWxmO1xyXG4gICAgICAgIH0pKGJvZHkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiByZXRvcm5vO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBnZXQgZXhwaXJlZCgpIDogYm9vbGVhblxyXG4gICAge1xyXG4gICAgICAgIGlmICh0aGlzLmV4cGlyZXMpIHtcclxuICAgICAgICAgICAgcmV0dXJuIERhdGUubm93KCkgPiB0aGlzLmV4cGlyZXMuZ2V0VGltZSgpXHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IHJlc291cmNlIG93bmVyIHBhc3N3b3JkIGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4zXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIE93bmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIE1ha2UgYSByZXF1ZXN0IG9uIGJlaGFsZiBvZiB0aGUgdXNlciBjcmVkZW50aWFscyB0byBnZXQgYW4gYWNjZXMgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVzZXJuYW1lXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHBhc3N3b3JkXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBPd25lckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcclxuLy8gICAgICAgcGFzc3dvcmQ6IHBhc3N3b3JkLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAncGFzc3dvcmQnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLyoqXHJcbiAqIFN1cHBvcnQgaW1wbGljaXQgT0F1dGggMi4wIGdyYW50LlxyXG4gKlxyXG4gKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjJcclxuICpcclxuICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIFRva2VuRmxvdyBcclxue1xyXG4gICAgY2xpZW50OiBDbGllbnRPQXV0aDI7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZ2V0VXJpKG9wdGlvbnM/OmFueSkge1xyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIGNyZWF0ZVVyaShvcHRpb25zLCAndG9rZW4nKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0VG9rZW4odXJpLCBzdGF0ZT8sIG9wdGlvbnM/KSBcclxuICAgIHtcclxuICAgICAgICAvL29wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIC8vIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbiAgICAgICAgLy8gdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbiAgICAgICAgLy8gaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1Nob3VsZCBtYXRjaCByZWRpcmVjdCB1cmk6ICcgKyB1cmkpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gSWYgbm8gcXVlcnkgc3RyaW5nIG9yIGZyYWdtZW50IGV4aXN0cywgd2Ugd29uJ3QgYmUgYWJsZSB0byBwYXJzZVxyXG4gICAgICAgIC8vIC8vIGFueSB1c2VmdWwgaW5mb3JtYXRpb24gZnJvbSB0aGUgdXJpLlxyXG4gICAgICAgIC8vIGlmICghdXJsLmhhc2ggJiYgIXVybC5zZWFyY2gpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyBFeHRyYWN0IGRhdGEgZnJvbSBib3RoIHRoZSBmcmFnbWVudCBhbmQgcXVlcnkgc3RyaW5nLiBUaGUgZnJhZ21lbnQgaXMgbW9zdFxyXG4gICAgICAgIC8vIGltcG9ydGFudCwgYnV0IHRoZSBxdWVyeSBzdHJpbmcgaXMgYWxzbyB1c2VkIGJlY2F1c2Ugc29tZSBPQXV0aCAyLjBcclxuICAgICAgICAvLyBpbXBsZW1lbnRhdGlvbnMgKEluc3RhZ3JhbSkgaGF2ZSBhIGJ1ZyB3aGVyZSBzdGF0ZSBpcyBwYXNzZWQgdmlhIHF1ZXJ5LlxyXG4gICAgICAgIC8vIHZhciBkYXRhID0gZXh0ZW5kKFxyXG4gICAgICAgIC8vICAgICB1cmwucXVlcnkgPyBwYXJzZVF1ZXJ5KHVybC5xdWVyeSkgOiB7fSxcclxuICAgICAgICAvLyAgICAgdXJsLmhhc2ggPyBwYXJzZVF1ZXJ5KHVybC5oYXNoLnN1YnN0cigxKSkgOiB7fVxyXG4gICAgICAgIC8vIClcclxuXHJcbiAgICAgICAgLy8gdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKVxyXG5cclxuICAgICAgICAvLyAvLyBDaGVjayBpZiB0aGUgcXVlcnkgc3RyaW5nIHdhcyBwb3B1bGF0ZWQgd2l0aCBhIGtub3duIGVycm9yLlxyXG4gICAgICAgIC8vIGlmIChlcnIpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIHdoZXRoZXIgdGhlIHN0YXRlIG1hdGNoZXMuXHJcbiAgICAgICAgLy8gaWYgKHN0YXRlICE9IG51bGwgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6ICcgKyBkYXRhLnN0YXRlKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIGZ1bmN0aW9uIFBhcnNlYXJVcmwodXJsOiBzdHJpbmcpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBpZih1cmwuaW5kZXhPZignIycpICE9PSAtMSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdXJsLnN1YnN0cih1cmwuaW5kZXhPZignIycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdXJsLnN1YnN0cih1cmwuaW5kZXhPZignPycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBsZXQgdXJsUGFyc2VhZGEgPSBQYXJzZWFyVXJsKHVyaSk7XHJcblxyXG4gICAgICAgIGxldCBkYXRhID0gdXJsUGFyc2VhZGE7XHJcblxyXG4gICAgICAgIC8vIEluaXRhbGl6ZSBhIG5ldyB0b2tlbiBhbmQgcmV0dXJuLlxyXG4gICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4odGhpcy5jbGllbnQsIGRhdGEpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuICAgIFxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBjbGllbnQgY3JlZGVudGlhbHMgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjRcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gQ3JlZGVudGlhbHNGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgdGhlIGNsaWVudCBjcmVkZW50aWFscy5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDcmVkZW50aWFsc0Zsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdjbGllbnRJZCcsXHJcbi8vICAgICAnY2xpZW50U2VjcmV0JyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnY2xpZW50X2NyZWRlbnRpYWxzJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGF1dGhvcml6YXRpb24gY29kZSBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDb2RlRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdlbmVyYXRlIHRoZSB1cmkgZm9yIGRvaW5nIHRoZSBmaXJzdCByZWRpcmVjdC5cclxuLy8gICpcclxuLy8gICogQHJldHVybiB7U3RyaW5nfVxyXG4vLyAgKi9cclxuLy8gQ29kZUZsb3cucHJvdG90eXBlLmdldFVyaSA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICdjb2RlJylcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdldCB0aGUgY29kZSB0b2tlbiBmcm9tIHRoZSByZWRpcmVjdGVkIHVyaSBhbmQgbWFrZSBhbm90aGVyIHJlcXVlc3QgZm9yXHJcbi8vICAqIHRoZSB1c2VyIGFjY2VzcyB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgdXJpXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIFtzdGF0ZV1cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJpLCBzdGF0ZSwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ3JlZGlyZWN0VXJpJyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgdXJsID0gcGFyc2VVcmwodXJpKVxyXG4vLyAgIHZhciBleHBlY3RlZFVybCA9IHBhcnNlVXJsKG9wdGlvbnMucmVkaXJlY3RVcmkpXHJcblxyXG4vLyAgIGlmICh1cmwucGF0aG5hbWUgIT09IGV4cGVjdGVkVXJsLnBhdGhuYW1lKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoIXVybC5zZWFyY2gpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdVbmFibGUgdG8gcHJvY2VzcyB1cmk6ICcgKyB1cmkpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgdmFyIGRhdGEgPSBwYXJzZVF1ZXJ5KHVybC5xdWVyeSlcclxuLy8gICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4vLyAgIGlmIChlcnIpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoc3RhdGUgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdJbnZhbGlkIHN0YXRlOicgKyBkYXRhLnN0YXRlKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIC8vIENoZWNrIHdoZXRoZXIgdGhlIHJlc3BvbnNlIGNvZGUgaXMgc2V0LlxyXG4vLyAgIGlmICghZGF0YS5jb2RlKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignTWlzc2luZyBjb2RlLCB1bmFibGUgdG8gcmVxdWVzdCB0b2tlbicpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUyksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIGNvZGU6IGRhdGEuY29kZSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ2F1dGhvcml6YXRpb25fY29kZScsXHJcbi8vICAgICAgIHJlZGlyZWN0X3VyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcclxuLy8gICAgICAgY2xpZW50X2lkOiBvcHRpb25zLmNsaWVudElkLFxyXG4vLyAgICAgICBjbGllbnRfc2VjcmV0OiBvcHRpb25zLmNsaWVudFNlY3JldFxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IEpTT04gV2ViIFRva2VuIChKV1QpIEJlYXJlciBUb2tlbiBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL2RyYWZ0LWlldGYtb2F1dGgtand0LWJlYXJlci0xMiNzZWN0aW9uLTIuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBKd3RCZWFyZXJGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgYSBKV1QgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge3N0cmluZ30gdG9rZW4gQSBKV1QgdG9rZW4uXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gSnd0QmVhcmVyRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodG9rZW4sIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgaGVhZGVycyA9IGV4dGVuZChERUZBVUxUX0hFQURFUlMpXHJcblxyXG4vLyAgIC8vIEF1dGhlbnRpY2F0aW9uIG9mIHRoZSBjbGllbnQgaXMgb3B0aW9uYWwsIGFzIGRlc2NyaWJlZCBpblxyXG4vLyAgIC8vIFNlY3Rpb24gMy4yLjEgb2YgT0F1dGggMi4wIFtSRkM2NzQ5XVxyXG4vLyAgIGlmIChvcHRpb25zLmNsaWVudElkKSB7XHJcbi8vICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogaGVhZGVycyxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAndXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlcicsXHJcbi8vICAgICAgIGFzc2VydGlvbjogdG9rZW5cclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcbiJdfQ==
