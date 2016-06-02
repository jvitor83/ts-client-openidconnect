// import 'xtend';
// import 'popsicle';
// import 'querystring';
// import 'url';
System.register([], function(exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    var __extends = (this && this.__extends) || function (d, b) {
        for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
    var hasOwnProperty, extend, DEFAULT_HEADERS, ERROR_RESPONSES, ClientOAuth2, ClientOAuth2Token, Flow, TokenFlow, Claimable, UserInfoResponse;
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
                    request.open(requestObject.method, requestObject.url, false);
                    var headers = requestObject.headers;
                    for (var header in headers) {
                        request.setRequestHeader(header, headers[header]);
                    }
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
                    this.identityToken = data.id_token;
                    this.expiresIn(data.expires_in);
                }
                Object.defineProperty(ClientOAuth2Token.prototype, "accessToken", {
                    get: function () {
                        if (this.expired) {
                            this.refresh();
                        }
                        return this._accessToken;
                    },
                    set: function (value) {
                        this._accessToken = value;
                    },
                    enumerable: true,
                    configurable: true
                });
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
            Flow = (function () {
                function Flow(client) {
                    this.client = client;
                }
                Flow.prototype.getUserInfo = function (accessToken) {
                    var response = this.client._request(requestOptions({
                        url: this.client.options.userInfoUri,
                        method: 'GET',
                        headers: extend(DEFAULT_HEADERS, {
                            Authorization: 'Bearer ' + accessToken
                        })
                    }, this.client.options));
                    var responseJSON = JSON.parse(response);
                    var userInfoResponse = new UserInfoResponse(responseJSON.sub);
                    userInfoResponse = extend(userInfoResponse, responseJSON);
                    return userInfoResponse;
                };
                return Flow;
            }());
            exports_1("Flow", Flow);
            /**
             * Support implicit OAuth 2.0 grant.
             *
             * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
             *
             * @param {ClientOAuth2} client
             */
            TokenFlow = (function (_super) {
                __extends(TokenFlow, _super);
                function TokenFlow() {
                    _super.apply(this, arguments);
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
            }(Flow));
            exports_1("TokenFlow", TokenFlow);
            Claimable = (function () {
                function Claimable() {
                }
                Claimable.prototype.getClaim = function (claimName) {
                    return this[claimName];
                };
                return Claimable;
            }());
            exports_1("Claimable", Claimable);
            UserInfoResponse = (function (_super) {
                __extends(UserInfoResponse, _super);
                function UserInfoResponse(sub) {
                    _super.call(this);
                    this.sub = sub;
                }
                return UserInfoResponse;
            }(Claimable));
            exports_1("UserInfoResponse", UserInfoResponse);
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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QUFDTixpRUFBaUU7QUFDakUsb0JBQW9CO0FBRXBCLG1EQUFtRDtBQUVuRCx1QkFBdUI7QUFDdkIsdUJBQXVCO0FBQ3ZCLE9BQU87QUFFUCwwQ0FBMEM7QUFFMUMsaUVBQWlFO0FBQ2pFLDRDQUE0QztBQUM1Qyw0QkFBNEI7QUFDNUIsOEVBQThFO0FBQzlFLE1BQU07QUFFTixpREFBaUQ7QUFDakQsbUNBQW1DO0FBQ25DLHNCQUFzQjtBQUN0Qix3QkFBd0I7QUFDeEIsY0FBYztBQUNkLDhDQUE4QztBQUM5QyxtRUFBbUU7QUFDbkUseUJBQXlCO0FBQ3pCLFFBQVE7QUFDUixpQkFBaUI7QUFDakIsZ0NBQWdDO0FBQ2hDLDhCQUE4QjtBQUM5Qix3REFBd0Q7QUFDeEQsU0FBUztBQUNULElBQUkiLCJmaWxlIjoic3JjL0NsaWVudC5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8vIGltcG9ydCAneHRlbmQnO1xyXG4vLyBpbXBvcnQgJ3BvcHNpY2xlJztcclxuLy8gaW1wb3J0ICdxdWVyeXN0cmluZyc7XHJcbi8vIGltcG9ydCAndXJsJztcclxuXHJcbnZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XHJcblxyXG52YXIgZXh0ZW5kID0gZnVuY3Rpb24gZXh0ZW5kKC4uLmFyZ3M6QXJyYXk8YW55Pik6YW55IHtcclxuICAgIHZhciB0YXJnZXQgPSB7fVxyXG5cclxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgIHZhciBzb3VyY2UgPSBhcmdzW2ldXHJcblxyXG4gICAgICAgIGZvciAodmFyIGtleSBpbiBzb3VyY2UpIHtcclxuICAgICAgICAgICAgaWYgKGhhc093blByb3BlcnR5LmNhbGwoc291cmNlLCBrZXkpKSB7XHJcbiAgICAgICAgICAgICAgICB0YXJnZXRba2V5XSA9IHNvdXJjZVtrZXldXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRhcmdldDtcclxufVxyXG5cclxuXHJcblxyXG4vL3ZhciBwb3BzaWNsZSAgOmFueTtcclxuLy92YXIgcGFyc2VRdWVyeSA6YW55O1xyXG4vL3ZhciBwYXJzZVVybCAgOmFueTtcclxuXHJcbi8vIHZhciBleHRlbmQgPSByZXF1aXJlKCd4dGVuZCcpXHJcbi8vIHZhciBwb3BzaWNsZSA9IHJlcXVpcmUoJ3BvcHNpY2xlJylcclxuLy8gdmFyIHBhcnNlUXVlcnkgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpLnBhcnNlXHJcbi8vIHZhciBwYXJzZVVybCA9IHJlcXVpcmUoJ3VybCcpLnBhcnNlXHJcblxyXG4vL3ZhciBidG9hID0gdHlwZW9mIEJ1ZmZlciA9PT0gJ2Z1bmN0aW9uJyA/IGJ0b2FCdWZmZXIgOiB3aW5kb3cuYnRvYVxyXG5cclxuLyoqXHJcbiAqIERlZmF1bHQgaGVhZGVycyBmb3IgZXhlY3V0aW5nIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHR5cGUge09iamVjdH1cclxuICovXHJcbnZhciBERUZBVUxUX0hFQURFUlMgPSB7XHJcbiAgJ0FjY2VwdCc6ICdhcHBsaWNhdGlvbi9qc29uLCBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnLFxyXG4gICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG59XHJcblxyXG4vKipcclxuICogRm9ybWF0IGVycm9yIHJlc3BvbnNlIHR5cGVzIHRvIHJlZ3VsYXIgc3RyaW5ncyBmb3IgZGlzcGxheWluZyB0byBjbGllbnRzLlxyXG4gKlxyXG4gKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjEuMi4xXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgRVJST1JfUkVTUE9OU0VTID0ge1xyXG4gICdpbnZhbGlkX3JlcXVlc3QnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3QgaXMgbWlzc2luZyBhIHJlcXVpcmVkIHBhcmFtZXRlciwgaW5jbHVkZXMgYW4nLFxyXG4gICAgJ2ludmFsaWQgcGFyYW1ldGVyIHZhbHVlLCBpbmNsdWRlcyBhIHBhcmFtZXRlciBtb3JlIHRoYW4nLFxyXG4gICAgJ29uY2UsIG9yIGlzIG90aGVyd2lzZSBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2NsaWVudCc6IFtcclxuICAgICdDbGllbnQgYXV0aGVudGljYXRpb24gZmFpbGVkIChlLmcuLCB1bmtub3duIGNsaWVudCwgbm8nLFxyXG4gICAgJ2NsaWVudCBhdXRoZW50aWNhdGlvbiBpbmNsdWRlZCwgb3IgdW5zdXBwb3J0ZWQnLFxyXG4gICAgJ2F1dGhlbnRpY2F0aW9uIG1ldGhvZCkuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2dyYW50JzogW1xyXG4gICAgJ1RoZSBwcm92aWRlZCBhdXRob3JpemF0aW9uIGdyYW50IChlLmcuLCBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlLCByZXNvdXJjZSBvd25lciBjcmVkZW50aWFscykgb3IgcmVmcmVzaCB0b2tlbiBpcycsXHJcbiAgICAnaW52YWxpZCwgZXhwaXJlZCwgcmV2b2tlZCwgZG9lcyBub3QgbWF0Y2ggdGhlIHJlZGlyZWN0aW9uJyxcclxuICAgICdVUkkgdXNlZCBpbiB0aGUgYXV0aG9yaXphdGlvbiByZXF1ZXN0LCBvciB3YXMgaXNzdWVkIHRvJyxcclxuICAgICdhbm90aGVyIGNsaWVudC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3VuYXV0aG9yaXplZF9jbGllbnQnOiBbXHJcbiAgICAnVGhlIGNsaWVudCBpcyBub3QgYXV0aG9yaXplZCB0byByZXF1ZXN0IGFuIGF1dGhvcml6YXRpb24nLFxyXG4gICAgJ2NvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bnN1cHBvcnRlZF9ncmFudF90eXBlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIGdyYW50IHR5cGUgaXMgbm90IHN1cHBvcnRlZCBieSB0aGUnLFxyXG4gICAgJ2F1dGhvcml6YXRpb24gc2VydmVyLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnYWNjZXNzX2RlbmllZCc6IFtcclxuICAgICdUaGUgcmVzb3VyY2Ugb3duZXIgb3IgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZGVuaWVkIHRoZSByZXF1ZXN0LidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfcmVzcG9uc2VfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZG9lcyBub3Qgc3VwcG9ydCBvYnRhaW5pbmcnLFxyXG4gICAgJ2FuIGF1dGhvcml6YXRpb24gY29kZSB1c2luZyB0aGlzIG1ldGhvZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfc2NvcGUnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3RlZCBzY29wZSBpcyBpbnZhbGlkLCB1bmtub3duLCBvciBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdzZXJ2ZXJfZXJyb3InOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGVuY291bnRlcmVkIGFuIHVuZXhwZWN0ZWQnLFxyXG4gICAgJ2NvbmRpdGlvbiB0aGF0IHByZXZlbnRlZCBpdCBmcm9tIGZ1bGZpbGxpbmcgdGhlIHJlcXVlc3QuJyxcclxuICAgICcoVGhpcyBlcnJvciBjb2RlIGlzIG5lZWRlZCBiZWNhdXNlIGEgNTAwIEludGVybmFsIFNlcnZlcicsXHJcbiAgICAnRXJyb3IgSFRUUCBzdGF0dXMgY29kZSBjYW5ub3QgYmUgcmV0dXJuZWQgdG8gdGhlIGNsaWVudCcsXHJcbiAgICAndmlhIGFuIEhUVFAgcmVkaXJlY3QuKSdcclxuICBdLmpvaW4oJyAnKSxcclxuICAndGVtcG9yYXJpbHlfdW5hdmFpbGFibGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGlzIGN1cnJlbnRseSB1bmFibGUgdG8gaGFuZGxlJyxcclxuICAgICd0aGUgcmVxdWVzdCBkdWUgdG8gYSB0ZW1wb3Jhcnkgb3ZlcmxvYWRpbmcgb3IgbWFpbnRlbmFuY2UnLFxyXG4gICAgJ29mIHRoZSBzZXJ2ZXIuJ1xyXG4gIF0uam9pbignICcpXHJcbn1cclxuXHJcblxyXG4vKipcclxuICogQ2hlY2sgaWYgcHJvcGVydGllcyBleGlzdCBvbiBhbiBvYmplY3QgYW5kIHRocm93IHdoZW4gdGhleSBhcmVuJ3QuXHJcbiAqXHJcbiAqIEB0aHJvd3Mge1R5cGVFcnJvcn0gSWYgYW4gZXhwZWN0ZWQgcHJvcGVydHkgaXMgbWlzc2luZy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9ialxyXG4gKiBAcGFyYW0ge0FycmF5fSAgcHJvcHNcclxuICovXHJcbmZ1bmN0aW9uIGV4cGVjdHMgKG9iaiwgcHJvcHMpIHtcclxuICBmb3IgKHZhciBpID0gMDsgaSA8IHByb3BzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICB2YXIgcHJvcCA9IHByb3BzW2ldXHJcblxyXG4gICAgaWYgKG9ialtwcm9wXSA9PSBudWxsKSB7XHJcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiJyArIHByb3AgKyAnXCIgdG8gZXhpc3QnKVxyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuLyoqXHJcbiAqIFB1bGwgYW4gYXV0aGVudGljYXRpb24gZXJyb3IgZnJvbSB0aGUgcmVzcG9uc2UgZGF0YS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSBkYXRhXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGdldEF1dGhFcnJvciAoZGF0YSkge1xyXG4gIHZhciBtZXNzYWdlID0gRVJST1JfUkVTUE9OU0VTW2RhdGEuZXJyb3JdIHx8XHJcbiAgICBkYXRhLmVycm9yIHx8XHJcbiAgICBkYXRhLmVycm9yX21lc3NhZ2VcclxuXHJcbiAgLy8gUmV0dXJuIGFuIGVycm9yIGluc3RhbmNlIHdpdGggdGhlIG1lc3NhZ2UgaWYgaXQgZXhpc3RzLlxyXG4gIHJldHVybiBtZXNzYWdlICYmIG5ldyBFcnJvcihtZXNzYWdlKVxyXG59XHJcblxyXG4vKipcclxuICogSGFuZGxlIHRoZSBhdXRoZW50aWNhdGlvbiByZXNwb25zZSBvYmplY3QuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gIHJlc1xyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuZnVuY3Rpb24gaGFuZGxlQXV0aFJlc3BvbnNlIChyZXMpIHtcclxuICB2YXIgZGF0YSA9IHJlcy5ib2R5O1xyXG4gIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSk7XHJcblxyXG4gIC8vIElmIHRoZSByZXNwb25zZSBjb250YWlucyBhbiBlcnJvciwgcmVqZWN0IHRoZSByZWZyZXNoIHRva2VuLlxyXG4gIGlmIChlcnIpIHtcclxuICAgIHJldHVybiBlcnI7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZGF0YTtcclxufVxyXG5cclxuLyoqXHJcbiAqIFNhbml0aXplIHRoZSBzY29wZXMgb3B0aW9uIHRvIGJlIGEgc3RyaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtBcnJheX0gIHNjb3Blc1xyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBzYW5pdGl6ZVNjb3BlIChzY29wZXMpIHtcclxuICByZXR1cm4gQXJyYXkuaXNBcnJheShzY29wZXMpID8gc2NvcGVzLmpvaW4oJyAnKSA6IHN0cmluZyhzY29wZXMpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGEgcmVxdWVzdCB1cmkgYmFzZWQgb24gYW4gb3B0aW9ucyBvYmplY3QgYW5kIHRva2VuIHR5cGUuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gb3B0aW9uc1xyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHRva2VuVHlwZVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBjcmVhdGVVcmkgKG9wdGlvbnMsIHRva2VuVHlwZSkge1xyXG4gIC8vIENoZWNrIHRoZSByZXF1aXJlZCBwYXJhbWV0ZXJzIGFyZSBzZXQuXHJcbiAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbiAgICAnY2xpZW50SWQnLFxyXG4gICAgJ3JlZGlyZWN0VXJpJyxcclxuICAgICdhdXRob3JpemF0aW9uVXJpJ1xyXG4gIF0pO1xyXG5cclxuICB2YXIgY2xpZW50SWQgPSBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5jbGllbnRJZCk7XHJcbiAgdmFyIHJlZGlyZWN0VXJpID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMucmVkaXJlY3RVcmkpO1xyXG4gIHZhciBzY29wZXMgPSBlbmNvZGVVUklDb21wb25lbnQoc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcykpO1xyXG4gIHZhciB1cmkgPSBvcHRpb25zLmF1dGhvcml6YXRpb25VcmkgKyAnP2NsaWVudF9pZD0nICsgY2xpZW50SWQgK1xyXG4gICAgJyZyZWRpcmVjdF91cmk9JyArIHJlZGlyZWN0VXJpICtcclxuICAgICcmc2NvcGU9JyArIHNjb3BlcyArXHJcbiAgICAnJnJlc3BvbnNlX3R5cGU9JyArIHRva2VuVHlwZTtcclxuXHJcbiAgaWYgKG9wdGlvbnMuc3RhdGUpIHtcclxuICAgIHVyaSArPSAnJnN0YXRlPScgKyBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5zdGF0ZSk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gdXJpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGJhc2ljIGF1dGggaGVhZGVyLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHVzZXJuYW1lXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gcGFzc3dvcmRcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gYXV0aCAodXNlcm5hbWUsIHBhc3N3b3JkKSB7XHJcbiAgcmV0dXJuICdCYXNpYyAnICsgYnRvYShzdHJpbmcodXNlcm5hbWUpICsgJzonICsgc3RyaW5nKHBhc3N3b3JkKSk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBFbnN1cmUgYSB2YWx1ZSBpcyBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSBzdHJcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc3RyaW5nIChzdHIpIHtcclxuICByZXR1cm4gc3RyID09IG51bGwgPyAnJyA6IFN0cmluZyhzdHIpO1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFJlcXVlc3RPcHRpb25zIHtcclxuICAgIGJvZHk6IGFueTtcclxuICAgIHF1ZXJ5OiBhbnk7XHJcbiAgICBoZWFkZXJzOiBhbnk7XHJcbiAgICBvcHRpb25zOiBhbnk7XHJcbiAgICBtZXRob2Q6IHN0cmluZztcclxuICAgIHVybDogc3RyaW5nO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIE1lcmdlIHJlcXVlc3Qgb3B0aW9ucyBmcm9tIGFuIG9wdGlvbnMgb2JqZWN0LlxyXG4gKi9cclxuZnVuY3Rpb24gcmVxdWVzdE9wdGlvbnMgKHJlcXVlc3RPcHRpb25zLCBvcHRpb25zKTogUmVxdWVzdE9wdGlvbnMge1xyXG5cclxuICByZXR1cm4gZXh0ZW5kKHJlcXVlc3RPcHRpb25zLCB7XHJcbiAgICBib2R5OiBleHRlbmQob3B0aW9ucy5ib2R5LCByZXF1ZXN0T3B0aW9ucy5ib2R5KSxcclxuICAgIHF1ZXJ5OiBleHRlbmQob3B0aW9ucy5xdWVyeSwgcmVxdWVzdE9wdGlvbnMucXVlcnkpLFxyXG4gICAgaGVhZGVyczogZXh0ZW5kKG9wdGlvbnMuaGVhZGVycywgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXHJcbiAgICBvcHRpb25zOiBleHRlbmQob3B0aW9ucy5vcHRpb25zLCByZXF1ZXN0T3B0aW9ucy5vcHRpb25zKVxyXG4gIH0pO1xyXG59XHJcblxyXG4vKipcclxuICogQ29uc3RydWN0IGFuIG9iamVjdCB0aGF0IGNhbiBoYW5kbGUgdGhlIG11bHRpcGxlIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDIge1xyXG4gICAgLy8gY29kZSA6IENvZGVGbG93O1xyXG4gICAgIHRva2VuIDogVG9rZW5GbG93O1xyXG4gICAgLy8gb3duZXIgOiBPd25lckZsb3c7XHJcbiAgICAvLyBjcmVkZW50aWFscyA6IENyZWRlbnRpYWxzRmxvdztcclxuICAgIC8vIGp3dCA6IEp3dEJlYXJlckZsb3c7XHJcbiAgICBvcHRpb25zIDphbnk7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKG9wdGlvbnM6IGFueSlcclxuICAgIHtcclxuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xyXG5cclxuICAgICAgICAvLyB0aGlzLmNvZGUgPSBuZXcgQ29kZUZsb3codGhpcyk7XHJcbiAgICAgICAgdGhpcy50b2tlbiA9IG5ldyBUb2tlbkZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5vd25lciA9IG5ldyBPd25lckZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5jcmVkZW50aWFscyA9IG5ldyBDcmVkZW50aWFsc0Zsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5qd3QgPSBuZXcgSnd0QmVhcmVyRmxvdyh0aGlzKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIGNyZWF0ZVRva2VuKGFjY2Vzczogc3RyaW5nLCByZWZyZXNoOiBzdHJpbmcsIHR5cGU6IHN0cmluZywgZGF0YTogYW55KVxyXG4gICAge1xyXG4gICAgICAgIHZhciBvcHRpb25zID0gZXh0ZW5kKFxyXG4gICAgICAgICAgICBkYXRhLFxyXG4gICAgICAgICAgICB0eXBlb2YgYWNjZXNzID09PSAnc3RyaW5nJyA/IHsgYWNjZXNzX3Rva2VuOiBhY2Nlc3MgfSA6IGFjY2VzcyxcclxuICAgICAgICAgICAgdHlwZW9mIHJlZnJlc2ggPT09ICdzdHJpbmcnID8geyByZWZyZXNoX3Rva2VuOiByZWZyZXNoIH0gOiByZWZyZXNoLFxyXG4gICAgICAgICAgICB0eXBlb2YgdHlwZSA9PT0gJ3N0cmluZycgPyB7IHRva2VuX3R5cGU6IHR5cGUgfSA6IHR5cGVcclxuICAgICAgICApO1xyXG5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMsIG9wdGlvbnMpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgX3JlcXVlc3QocmVxdWVzdE9iamVjdCA6IFJlcXVlc3RPcHRpb25zKSA6YW55IFxyXG4gICAge1xyXG4gICAgICAgIGxldCByZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5vcGVuKHJlcXVlc3RPYmplY3QubWV0aG9kLCByZXF1ZXN0T2JqZWN0LnVybCwgZmFsc2UpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBoZWFkZXJzID0gcmVxdWVzdE9iamVjdC5oZWFkZXJzO1xyXG4gICAgICAgIGZvcihsZXQgaGVhZGVyIGluIGhlYWRlcnMpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoaGVhZGVyLCBoZWFkZXJzW2hlYWRlcl0pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICByZXF1ZXN0LnNlbmQocmVxdWVzdE9iamVjdC5ib2R5KTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gcmVxdWVzdC5yZXNwb25zZTtcclxuICAgICAgICBcclxuICAgIC8vICAgcmV0dXJuIHRoaXMucmVxdWVzdChyZXF1ZXN0T2JqZWN0KVxyXG4gICAgLy8gICAgIC50aGVuKGZ1bmN0aW9uIChyZXMpIHtcclxuICAgIC8vICAgICAgIGlmIChyZXMuc3RhdHVzIDwgMjAwIHx8IHJlcy5zdGF0dXMgPj0gMzk5KSB7XHJcbiAgICAvLyAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoJ0hUVFAgc3RhdHVzICcgKyByZXMuc3RhdHVzKVxyXG4gICAgLy8gICAgICAgICBlcnIuc3RhdHVzID0gcmVzLnN0YXR1c1xyXG4gICAgLy8gICAgICAgICBlcnIuYm9keSA9IHJlcy5ib2R5XHJcbiAgICAvLyAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbiAgICAvLyAgICAgICB9XHJcblxyXG4gICAgLy8gICAgICAgcmV0dXJuIHJlc1xyXG4gICAgLy8gICAgIH0pXHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBBbGlhcyB0aGUgdG9rZW4gY29uc3RydWN0b3IuXHJcbiAqXHJcbiAqIEB0eXBlIHtGdW5jdGlvbn1cclxuICovXHJcbi8vQ2xpZW50T0F1dGgyLlRva2VuID0gQ2xpZW50T0F1dGgyVG9rZW5cclxuXHJcblxyXG4vKipcclxuICogVXNpbmcgdGhlIGJ1aWx0LWluIHJlcXVlc3QgbWV0aG9kLCB3ZSdsbCBhdXRvbWF0aWNhbGx5IGF0dGVtcHQgdG8gcGFyc2VcclxuICogdGhlIHJlc3BvbnNlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXF1ZXN0T2JqZWN0XHJcbiAqIEByZXR1cm4ge1Byb21pc2V9XHJcbiAqL1xyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTZXQgYHBvcHNpY2xlYCBhcyB0aGUgZGVmYXVsdCByZXF1ZXN0IG1ldGhvZC5cclxuLy8gICovXHJcbi8vIENsaWVudE9BdXRoMi5wcm90b3R5cGUucmVxdWVzdCA9IHBvcHNpY2xlLnJlcXVlc3RcclxuXHJcbi8qKlxyXG4gKiBHZW5lcmFsIHB1cnBvc2UgY2xpZW50IHRva2VuIGdlbmVyYXRvci5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IGNsaWVudFxyXG4gKiBAcGFyYW0ge09iamVjdH0gZGF0YVxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIENsaWVudE9BdXRoMlRva2VuXHJcbnsgXHJcbiAgICBjbGllbnQgOkNsaWVudE9BdXRoMjtcclxuICAgIGRhdGEgOmFueTtcclxuICAgIHRva2VuVHlwZSA6c3RyaW5nO1xyXG4gICAgcmVmcmVzaFRva2VuIDpzdHJpbmc7XHJcbiAgICBleHBpcmVzIDpEYXRlO1xyXG4gICAgaWRlbnRpdHlUb2tlbjogc3RyaW5nO1xyXG4gICAgXHJcbiAgICBfYWNjZXNzVG9rZW4gOnN0cmluZztcclxuICAgIFxyXG4gICAgXHJcbiAgICBnZXQgYWNjZXNzVG9rZW4oKSA6c3RyaW5nXHJcbiAgICB7XHJcbiAgICAgICAgaWYodGhpcy5leHBpcmVkKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5fYWNjZXNzVG9rZW47XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHNldCBhY2Nlc3NUb2tlbih2YWx1ZTpzdHJpbmcpIFxyXG4gICAge1xyXG4gICAgICAgIHRoaXMuX2FjY2Vzc1Rva2VuID0gdmFsdWU7XHJcbiAgICB9XHJcbiAgICBcclxuXHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCwgZGF0YSkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgICAgIHRoaXMuZGF0YSA9IGRhdGE7XHJcbiAgICAgICAgdGhpcy50b2tlblR5cGUgPSBkYXRhLnRva2VuX3R5cGUgJiYgZGF0YS50b2tlbl90eXBlLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgdGhpcy5hY2Nlc3NUb2tlbiA9IGRhdGEuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuID0gZGF0YS5yZWZyZXNoX3Rva2VuO1xyXG4gICAgICAgIHRoaXMuaWRlbnRpdHlUb2tlbiA9IGRhdGEuaWRfdG9rZW47XHJcblxyXG4gICAgICAgIHRoaXMuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIGV4cGlyZXNJbihkdXJhdGlvbilcclxuICAgIHtcclxuICAgICAgICBpZiAoIWlzTmFOKGR1cmF0aW9uKSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcy5zZXRTZWNvbmRzKHRoaXMuZXhwaXJlcy5nZXRTZWNvbmRzKCkgKyBkdXJhdGlvbik7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2VcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IHVuZGVmaW5lZDtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZXhwaXJlcztcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHNpZ24ocmVxdWVzdE9iamVjdCkge1xyXG4gICAgICAgIGlmICghdGhpcy5hY2Nlc3NUb2tlbikge1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1VuYWJsZSB0byBzaWduIHdpdGhvdXQgYWNjZXNzIHRva2VuJylcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycyB8fCB7fVxyXG5cclxuICAgICAgICBpZiAodGhpcy50b2tlblR5cGUgPT09ICdiZWFyZXInKSB7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5BdXRob3JpemF0aW9uID0gJ0JlYXJlciAnICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB2YXIgcGFydHMgPSByZXF1ZXN0T2JqZWN0LnVybC5zcGxpdCgnIycpO1xyXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSAnYWNjZXNzX3Rva2VuPScgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgICAgICB2YXIgdXJsID0gcGFydHNbMF0ucmVwbGFjZSgvWz8mXWFjY2Vzc190b2tlbj1bXiYjXS8sICcnKTtcclxuICAgICAgICAgICAgdmFyIGZyYWdtZW50ID0gcGFydHNbMV0gPyAnIycgKyBwYXJ0c1sxXSA6ICcnO1xyXG5cclxuICAgICAgICAgICAgLy8gUHJlcGVuZCB0aGUgY29ycmVjdCBxdWVyeSBzdHJpbmcgcGFyYW1ldGVyIHRvIHRoZSB1cmwuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QudXJsID0gdXJsICsgKHVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgKyB0b2tlbiArIGZyYWdtZW50O1xyXG5cclxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBhdm9pZCBzdG9yaW5nIHRoZSB1cmwgaW4gcHJveGllcywgc2luY2UgdGhlIGFjY2VzcyB0b2tlblxyXG4gICAgICAgICAgICAvLyBpcyBleHBvc2VkIGluIHRoZSBxdWVyeSBwYXJhbWV0ZXJzLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuUHJhZ21hID0gJ25vLXN0b3JlJztcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzWydDYWNoZS1Db250cm9sJ10gPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3RPYmplY3Q7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyByZXF1ZXN0KG9wdGlvbnMpIHtcclxuICAgICAgICBsZXQgcmVxdWVzdE9wdGlvbnNSZXN1bHQgPSByZXF1ZXN0T3B0aW9ucyh0aGlzLnNpZ24ob3B0aW9ucyksIHRoaXMuY2xpZW50Lm9wdGlvbnMpO1xyXG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9uc1Jlc3VsdCk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIHJlZnJlc2gob3B0aW9ucz8pOmFueSB7XHJcbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xyXG5cclxuICAgICAgICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpO1xyXG5cclxuICAgICAgICBpZiAoIXRoaXMucmVmcmVzaFRva2VuKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBuZXcgRXJyb3IoJ05vIHJlZnJlc2ggdG9rZW4gc2V0Jyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmVzcG9uc2UgPSB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbiAgICAgICAgICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuICAgICAgICAgICAgfSksXHJcbiAgICAgICAgICAgIGJvZHk6IHtcclxuICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXHJcbiAgICAgICAgICAgIGdyYW50X3R5cGU6ICdyZWZyZXNoX3Rva2VuJ1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSwgb3B0aW9ucykpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBib2R5ID0gaGFuZGxlQXV0aFJlc3BvbnNlKHJlc3BvbnNlKTtcclxuICAgICAgICBcclxuICAgICAgICAvL1RPRE86IFRyYXRhciBxdWFuZG8gZXhjZXB0aW9uXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJldG9ybm8gPSAoZnVuY3Rpb24gKGRhdGEpIHtcclxuICAgICAgICAgICAgc2VsZi5hY2Nlc3NUb2tlbiA9IGRhdGEuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgICAgICBzZWxmLnJlZnJlc2hUb2tlbiA9IGRhdGEucmVmcmVzaF90b2tlbjtcclxuXHJcbiAgICAgICAgICAgIHNlbGYuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcblxyXG4gICAgICAgICAgICByZXR1cm4gc2VsZjtcclxuICAgICAgICB9KShib2R5KTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gcmV0b3JubztcclxuICAgIH1cclxuICAgIFxyXG4gICAgZ2V0IGV4cGlyZWQoKSA6IGJvb2xlYW5cclxuICAgIHtcclxuICAgICAgICBpZiAodGhpcy5leHBpcmVzKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBEYXRlLm5vdygpID4gdGhpcy5leHBpcmVzLmdldFRpbWUoKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgICAgICBcclxuXHJcbiAgICAgICAgXHJcbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IHJlc291cmNlIG93bmVyIHBhc3N3b3JkIGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4zXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIE93bmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIE1ha2UgYSByZXF1ZXN0IG9uIGJlaGFsZiBvZiB0aGUgdXNlciBjcmVkZW50aWFscyB0byBnZXQgYW4gYWNjZXMgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVzZXJuYW1lXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHBhc3N3b3JkXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBPd25lckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcclxuLy8gICAgICAgcGFzc3dvcmQ6IHBhc3N3b3JkLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAncGFzc3dvcmQnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEZsb3dcclxue1xyXG4gICAgY2xpZW50OiBDbGllbnRPQXV0aDI7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZ2V0VXNlckluZm8oYWNjZXNzVG9rZW46IHN0cmluZykgOiBVc2VySW5mb1Jlc3BvbnNlXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgIHVybDogdGhpcy5jbGllbnQub3B0aW9ucy51c2VySW5mb1VyaSxcclxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxyXG4gICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgYWNjZXNzVG9rZW5cclxuICAgICAgICB9KVxyXG4gICAgICAgIH0sIHRoaXMuY2xpZW50Lm9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmVzcG9uc2VKU09OID0gSlNPTi5wYXJzZShyZXNwb25zZSk7XHJcbiAgICAgICAgbGV0IHVzZXJJbmZvUmVzcG9uc2UgPSBuZXcgVXNlckluZm9SZXNwb25zZShyZXNwb25zZUpTT04uc3ViKTtcclxuICAgICAgICB1c2VySW5mb1Jlc3BvbnNlID0gZXh0ZW5kKHVzZXJJbmZvUmVzcG9uc2UsIHJlc3BvbnNlSlNPTik7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHVzZXJJbmZvUmVzcG9uc2U7XHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTdXBwb3J0IGltcGxpY2l0IE9BdXRoIDIuMCBncmFudC5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4yXHJcbiAqXHJcbiAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuICovXHJcbmV4cG9ydCBjbGFzcyBUb2tlbkZsb3cgZXh0ZW5kcyBGbG93XHJcbntcclxuICAgIHB1YmxpYyBnZXRVcmkob3B0aW9ucz86YW55KSB7XHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICd0b2tlbicpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRUb2tlbih1cmksIHN0YXRlPywgb3B0aW9ucz8pIFxyXG4gICAge1xyXG4gICAgICAgIC8vb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgLy8gdmFyIHVybCA9IHBhcnNlVXJsKHVyaSlcclxuICAgICAgICAvLyB2YXIgZXhwZWN0ZWRVcmwgPSBwYXJzZVVybChvcHRpb25zLnJlZGlyZWN0VXJpKVxyXG5cclxuICAgICAgICAvLyBpZiAodXJsLnBhdGhuYW1lICE9PSBleHBlY3RlZFVybC5wYXRobmFtZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyAvLyBJZiBubyBxdWVyeSBzdHJpbmcgb3IgZnJhZ21lbnQgZXhpc3RzLCB3ZSB3b24ndCBiZSBhYmxlIHRvIHBhcnNlXHJcbiAgICAgICAgLy8gLy8gYW55IHVzZWZ1bCBpbmZvcm1hdGlvbiBmcm9tIHRoZSB1cmkuXHJcbiAgICAgICAgLy8gaWYgKCF1cmwuaGFzaCAmJiAhdXJsLnNlYXJjaCkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignVW5hYmxlIHRvIHByb2Nlc3MgdXJpOiAnICsgdXJpKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIEV4dHJhY3QgZGF0YSBmcm9tIGJvdGggdGhlIGZyYWdtZW50IGFuZCBxdWVyeSBzdHJpbmcuIFRoZSBmcmFnbWVudCBpcyBtb3N0XHJcbiAgICAgICAgLy8gaW1wb3J0YW50LCBidXQgdGhlIHF1ZXJ5IHN0cmluZyBpcyBhbHNvIHVzZWQgYmVjYXVzZSBzb21lIE9BdXRoIDIuMFxyXG4gICAgICAgIC8vIGltcGxlbWVudGF0aW9ucyAoSW5zdGFncmFtKSBoYXZlIGEgYnVnIHdoZXJlIHN0YXRlIGlzIHBhc3NlZCB2aWEgcXVlcnkuXHJcbiAgICAgICAgLy8gdmFyIGRhdGEgPSBleHRlbmQoXHJcbiAgICAgICAgLy8gICAgIHVybC5xdWVyeSA/IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KSA6IHt9LFxyXG4gICAgICAgIC8vICAgICB1cmwuaGFzaCA/IHBhcnNlUXVlcnkodXJsLmhhc2guc3Vic3RyKDEpKSA6IHt9XHJcbiAgICAgICAgLy8gKVxyXG5cclxuICAgICAgICAvLyB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIGlmIHRoZSBxdWVyeSBzdHJpbmcgd2FzIHBvcHVsYXRlZCB3aXRoIGEga25vd24gZXJyb3IuXHJcbiAgICAgICAgLy8gaWYgKGVycikge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gQ2hlY2sgd2hldGhlciB0aGUgc3RhdGUgbWF0Y2hlcy5cclxuICAgICAgICAvLyBpZiAoc3RhdGUgIT0gbnVsbCAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignSW52YWxpZCBzdGF0ZTogJyArIGRhdGEuc3RhdGUpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgZnVuY3Rpb24gUGFyc2VhclVybCh1cmw6IHN0cmluZylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKHVybC5pbmRleE9mKCcjJykgIT09IC0xKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdXJsLnN1YnN0cih1cmwuaW5kZXhPZignIycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJz8nKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IHVybFBhcnNlYWRhID0gUGFyc2VhclVybCh1cmkpO1xyXG5cclxuICAgICAgICBsZXQgZGF0YSA9IHVybFBhcnNlYWRhO1xyXG5cclxuICAgICAgICAvLyBJbml0YWxpemUgYSBuZXcgdG9rZW4gYW5kIHJldHVybi5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMuY2xpZW50LCBkYXRhKTtcclxuICAgIH1cclxuICAgXHJcbn1cclxuICAgIFxyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQ2xhaW1hYmxlXHJcbntcclxuICAgIGdldENsYWltKGNsYWltTmFtZTogc3RyaW5nKVxyXG4gICAge1xyXG4gICAgICAgIHJldHVybiAoPGFueT50aGlzKVtjbGFpbU5hbWVdO1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgVXNlckluZm9SZXNwb25zZSBleHRlbmRzIENsYWltYWJsZVxyXG57XHJcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3ViOnN0cmluZykgXHJcbiAgICB7XHJcbiAgICAgICAgc3VwZXIoKTtcclxuICAgIH1cclxufVxyXG4gICAgXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGNsaWVudCBjcmVkZW50aWFscyBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuNFxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDcmVkZW50aWFsc0Zsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyB0aGUgY2xpZW50IGNyZWRlbnRpYWxzLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENyZWRlbnRpYWxzRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAob3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICdjbGllbnRfY3JlZGVudGlhbHMnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgYXV0aG9yaXphdGlvbiBjb2RlIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIENvZGVGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2VuZXJhdGUgdGhlIHVyaSBmb3IgZG9pbmcgdGhlIGZpcnN0IHJlZGlyZWN0LlxyXG4vLyAgKlxyXG4vLyAgKiBAcmV0dXJuIHtTdHJpbmd9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VXJpID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiBjcmVhdGVVcmkob3B0aW9ucywgJ2NvZGUnKVxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2V0IHRoZSBjb2RlIHRva2VuIGZyb20gdGhlIHJlZGlyZWN0ZWQgdXJpIGFuZCBtYWtlIGFub3RoZXIgcmVxdWVzdCBmb3JcclxuLy8gICogdGhlIHVzZXIgYWNjZXNzIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICB1cmlcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgW3N0YXRlXVxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENvZGVGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1cmksIHN0YXRlLCBvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbi8vICAgICAnY2xpZW50SWQnLFxyXG4vLyAgICAgJ2NsaWVudFNlY3JldCcsXHJcbi8vICAgICAncmVkaXJlY3RVcmknLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbi8vICAgdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbi8vICAgaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdTaG91bGQgbWF0Y2ggcmVkaXJlY3QgdXJpOiAnICsgdXJpKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmICghdXJsLnNlYXJjaCkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICB2YXIgZGF0YSA9IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KVxyXG4vLyAgIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSlcclxuXHJcbi8vICAgaWYgKGVycikge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmIChzdGF0ZSAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6JyArIGRhdGEuc3RhdGUpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgLy8gQ2hlY2sgd2hldGhlciB0aGUgcmVzcG9uc2UgY29kZSBpcyBzZXQuXHJcbi8vICAgaWYgKCFkYXRhLmNvZGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdNaXNzaW5nIGNvZGUsIHVuYWJsZSB0byByZXF1ZXN0IHRva2VuJykpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTKSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgY29kZTogZGF0YS5jb2RlLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnYXV0aG9yaXphdGlvbl9jb2RlJyxcclxuLy8gICAgICAgcmVkaXJlY3RfdXJpOiBvcHRpb25zLnJlZGlyZWN0VXJpLFxyXG4vLyAgICAgICBjbGllbnRfaWQ6IG9wdGlvbnMuY2xpZW50SWQsXHJcbi8vICAgICAgIGNsaWVudF9zZWNyZXQ6IG9wdGlvbnMuY2xpZW50U2VjcmV0XHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgSlNPTiBXZWIgVG9rZW4gKEpXVCkgQmVhcmVyIFRva2VuIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvZHJhZnQtaWV0Zi1vYXV0aC1qd3QtYmVhcmVyLTEyI3NlY3Rpb24tMi4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIEp3dEJlYXJlckZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyBhIEpXVCB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7c3RyaW5nfSB0b2tlbiBBIEpXVCB0b2tlbi5cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBKd3RCZWFyZXJGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh0b2tlbiwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciBoZWFkZXJzID0gZXh0ZW5kKERFRkFVTFRfSEVBREVSUylcclxuXHJcbi8vICAgLy8gQXV0aGVudGljYXRpb24gb2YgdGhlIGNsaWVudCBpcyBvcHRpb25hbCwgYXMgZGVzY3JpYmVkIGluXHJcbi8vICAgLy8gU2VjdGlvbiAzLjIuMSBvZiBPQXV0aCAyLjAgW1JGQzY3NDldXHJcbi8vICAgaWYgKG9wdGlvbnMuY2xpZW50SWQpIHtcclxuLy8gICAgIGhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBoZWFkZXJzLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICd1cm46aWV0ZjpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTpqd3QtYmVhcmVyJyxcclxuLy8gICAgICAgYXNzZXJ0aW9uOiB0b2tlblxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuIl19
