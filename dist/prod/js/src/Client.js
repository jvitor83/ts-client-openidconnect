System.register([], function(exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    var __extends = (this && this.__extends) || function (d, b) {
        for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
    var hasOwnProperty, extend, DEFAULT_HEADERS, ERROR_RESPONSES, ClientOAuth2, ClientOAuth2Token, TokenFlow, Claimable, UserInfoResponse;
    function expects(obj, props) {
        for (var i = 0; i < props.length; i++) {
            var prop = props[i];
            if (obj[prop] == null) {
                throw new TypeError('Expected "' + prop + '" to exist');
            }
        }
    }
    function getAuthError(data) {
        var message = ERROR_RESPONSES[data.error] ||
            data.error ||
            data.error_message;
        return message && new Error(message);
    }
    function handleAuthResponse(res) {
        var data = res.body;
        var err = getAuthError(data);
        if (err) {
            return err;
        }
        return data;
    }
    function sanitizeScope(scopes) {
        return Array.isArray(scopes) ? scopes.join(' ') : string(scopes);
    }
    function createUri(options, tokenType) {
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
    function auth(username, password) {
        return 'Basic ' + btoa(string(username) + ':' + string(password));
    }
    function string(str) {
        return str == null ? '' : String(str);
    }
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
            DEFAULT_HEADERS = {
                'Accept': 'application/json, application/x-www-form-urlencoded',
                'Content-Type': 'application/x-www-form-urlencoded'
            };
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
            ClientOAuth2 = (function () {
                function ClientOAuth2(options) {
                    this.options = options;
                    this.token = new TokenFlow(this);
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
                };
                return ClientOAuth2;
            }());
            exports_1("ClientOAuth2", ClientOAuth2);
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
                        requestObject.url = url + (url.indexOf('?') > -1 ? '&' : '?') + token + fragment;
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
                ClientOAuth2Token.prototype.getUserInfo = function (accessToken) {
                    var response = this.client._request(requestOptions({
                        url: this.client.options.userInfoUri,
                        method: 'GET',
                        headers: extend(DEFAULT_HEADERS, {
                            Authorization: 'Bearer ' + accessToken
                        })
                    }, this.client.options));
                    var userInfoResponse = new UserInfoResponse(response.sub);
                    userInfoResponse = extend(userInfoResponse, response);
                    return userInfoResponse;
                };
                return ClientOAuth2Token;
            }());
            exports_1("ClientOAuth2Token", ClientOAuth2Token);
            TokenFlow = (function () {
                function TokenFlow(client) {
                    this.client = client;
                }
                TokenFlow.prototype.getUri = function (options) {
                    options = extend(this.client.options, options);
                    return createUri(options, 'token');
                };
                TokenFlow.prototype.getToken = function (uri, state, options) {
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
                    return new ClientOAuth2Token(this.client, data);
                };
                return TokenFlow;
            }());
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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TztnQkFHN0IsQ0FBQztnQkFDTCx1QkFBQztZQUFELENBTkEsQUFNQyxDQU5xQyxTQUFTLEdBTTlDO1lBTkQsK0NBTUMsQ0FBQSIsImZpbGUiOiJDbGllbnQuanMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBpbXBvcnQgJ3h0ZW5kJztcclxuLy8gaW1wb3J0ICdwb3BzaWNsZSc7XHJcbi8vIGltcG9ydCAncXVlcnlzdHJpbmcnO1xyXG4vLyBpbXBvcnQgJ3VybCc7XHJcblxyXG52YXIgaGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xyXG5cclxudmFyIGV4dGVuZCA9IGZ1bmN0aW9uIGV4dGVuZCguLi5hcmdzOkFycmF5PGFueT4pOmFueSB7XHJcbiAgICB2YXIgdGFyZ2V0ID0ge31cclxuXHJcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICB2YXIgc291cmNlID0gYXJnc1tpXVxyXG5cclxuICAgICAgICBmb3IgKHZhciBrZXkgaW4gc291cmNlKSB7XHJcbiAgICAgICAgICAgIGlmIChoYXNPd25Qcm9wZXJ0eS5jYWxsKHNvdXJjZSwga2V5KSkge1xyXG4gICAgICAgICAgICAgICAgdGFyZ2V0W2tleV0gPSBzb3VyY2Vba2V5XVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0YXJnZXQ7XHJcbn1cclxuXHJcblxyXG5cclxuLy92YXIgcG9wc2ljbGUgIDphbnk7XHJcbi8vdmFyIHBhcnNlUXVlcnkgOmFueTtcclxuLy92YXIgcGFyc2VVcmwgIDphbnk7XHJcblxyXG4vLyB2YXIgZXh0ZW5kID0gcmVxdWlyZSgneHRlbmQnKVxyXG4vLyB2YXIgcG9wc2ljbGUgPSByZXF1aXJlKCdwb3BzaWNsZScpXHJcbi8vIHZhciBwYXJzZVF1ZXJ5ID0gcmVxdWlyZSgncXVlcnlzdHJpbmcnKS5wYXJzZVxyXG4vLyB2YXIgcGFyc2VVcmwgPSByZXF1aXJlKCd1cmwnKS5wYXJzZVxyXG5cclxuLy92YXIgYnRvYSA9IHR5cGVvZiBCdWZmZXIgPT09ICdmdW5jdGlvbicgPyBidG9hQnVmZmVyIDogd2luZG93LmJ0b2FcclxuXHJcbi8qKlxyXG4gKiBEZWZhdWx0IGhlYWRlcnMgZm9yIGV4ZWN1dGluZyBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgREVGQVVMVF9IRUFERVJTID0ge1xyXG4gICdBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbiwgYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcclxuICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxufVxyXG5cclxuLyoqXHJcbiAqIEZvcm1hdCBlcnJvciByZXNwb25zZSB0eXBlcyB0byByZWd1bGFyIHN0cmluZ3MgZm9yIGRpc3BsYXlpbmcgdG8gY2xpZW50cy5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xLjIuMVxyXG4gKlxyXG4gKiBAdHlwZSB7T2JqZWN0fVxyXG4gKi9cclxudmFyIEVSUk9SX1JFU1BPTlNFUyA9IHtcclxuICAnaW52YWxpZF9yZXF1ZXN0JzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0IGlzIG1pc3NpbmcgYSByZXF1aXJlZCBwYXJhbWV0ZXIsIGluY2x1ZGVzIGFuJyxcclxuICAgICdpbnZhbGlkIHBhcmFtZXRlciB2YWx1ZSwgaW5jbHVkZXMgYSBwYXJhbWV0ZXIgbW9yZSB0aGFuJyxcclxuICAgICdvbmNlLCBvciBpcyBvdGhlcndpc2UgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9jbGllbnQnOiBbXHJcbiAgICAnQ2xpZW50IGF1dGhlbnRpY2F0aW9uIGZhaWxlZCAoZS5nLiwgdW5rbm93biBjbGllbnQsIG5vJyxcclxuICAgICdjbGllbnQgYXV0aGVudGljYXRpb24gaW5jbHVkZWQsIG9yIHVuc3VwcG9ydGVkJyxcclxuICAgICdhdXRoZW50aWNhdGlvbiBtZXRob2QpLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9ncmFudCc6IFtcclxuICAgICdUaGUgcHJvdmlkZWQgYXV0aG9yaXphdGlvbiBncmFudCAoZS5nLiwgYXV0aG9yaXphdGlvbicsXHJcbiAgICAnY29kZSwgcmVzb3VyY2Ugb3duZXIgY3JlZGVudGlhbHMpIG9yIHJlZnJlc2ggdG9rZW4gaXMnLFxyXG4gICAgJ2ludmFsaWQsIGV4cGlyZWQsIHJldm9rZWQsIGRvZXMgbm90IG1hdGNoIHRoZSByZWRpcmVjdGlvbicsXHJcbiAgICAnVVJJIHVzZWQgaW4gdGhlIGF1dGhvcml6YXRpb24gcmVxdWVzdCwgb3Igd2FzIGlzc3VlZCB0bycsXHJcbiAgICAnYW5vdGhlciBjbGllbnQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bmF1dGhvcml6ZWRfY2xpZW50JzogW1xyXG4gICAgJ1RoZSBjbGllbnQgaXMgbm90IGF1dGhvcml6ZWQgdG8gcmVxdWVzdCBhbiBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlIHVzaW5nIHRoaXMgbWV0aG9kLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfZ3JhbnRfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBncmFudCB0eXBlIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlJyxcclxuICAgICdhdXRob3JpemF0aW9uIHNlcnZlci4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2FjY2Vzc19kZW5pZWQnOiBbXHJcbiAgICAnVGhlIHJlc291cmNlIG93bmVyIG9yIGF1dGhvcml6YXRpb24gc2VydmVyIGRlbmllZCB0aGUgcmVxdWVzdC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3Vuc3VwcG9ydGVkX3Jlc3BvbnNlX3R5cGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGRvZXMgbm90IHN1cHBvcnQgb2J0YWluaW5nJyxcclxuICAgICdhbiBhdXRob3JpemF0aW9uIGNvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX3Njb3BlJzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0ZWQgc2NvcGUgaXMgaW52YWxpZCwgdW5rbm93biwgb3IgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnc2VydmVyX2Vycm9yJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBlbmNvdW50ZXJlZCBhbiB1bmV4cGVjdGVkJyxcclxuICAgICdjb25kaXRpb24gdGhhdCBwcmV2ZW50ZWQgaXQgZnJvbSBmdWxmaWxsaW5nIHRoZSByZXF1ZXN0LicsXHJcbiAgICAnKFRoaXMgZXJyb3IgY29kZSBpcyBuZWVkZWQgYmVjYXVzZSBhIDUwMCBJbnRlcm5hbCBTZXJ2ZXInLFxyXG4gICAgJ0Vycm9yIEhUVFAgc3RhdHVzIGNvZGUgY2Fubm90IGJlIHJldHVybmVkIHRvIHRoZSBjbGllbnQnLFxyXG4gICAgJ3ZpYSBhbiBIVFRQIHJlZGlyZWN0LiknXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3RlbXBvcmFyaWx5X3VuYXZhaWxhYmxlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBpcyBjdXJyZW50bHkgdW5hYmxlIHRvIGhhbmRsZScsXHJcbiAgICAndGhlIHJlcXVlc3QgZHVlIHRvIGEgdGVtcG9yYXJ5IG92ZXJsb2FkaW5nIG9yIG1haW50ZW5hbmNlJyxcclxuICAgICdvZiB0aGUgc2VydmVyLidcclxuICBdLmpvaW4oJyAnKVxyXG59XHJcblxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGlmIHByb3BlcnRpZXMgZXhpc3Qgb24gYW4gb2JqZWN0IGFuZCB0aHJvdyB3aGVuIHRoZXkgYXJlbid0LlxyXG4gKlxyXG4gKiBAdGhyb3dzIHtUeXBlRXJyb3J9IElmIGFuIGV4cGVjdGVkIHByb3BlcnR5IGlzIG1pc3NpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcclxuICogQHBhcmFtIHtBcnJheX0gIHByb3BzXHJcbiAqL1xyXG5mdW5jdGlvbiBleHBlY3RzIChvYmosIHByb3BzKSB7XHJcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwcm9wcy5sZW5ndGg7IGkrKykge1xyXG4gICAgdmFyIHByb3AgPSBwcm9wc1tpXVxyXG5cclxuICAgIGlmIChvYmpbcHJvcF0gPT0gbnVsbCkge1xyXG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcIicgKyBwcm9wICsgJ1wiIHRvIGV4aXN0JylcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBQdWxsIGFuIGF1dGhlbnRpY2F0aW9uIGVycm9yIGZyb20gdGhlIHJlc3BvbnNlIGRhdGEuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gZGF0YVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBnZXRBdXRoRXJyb3IgKGRhdGEpIHtcclxuICB2YXIgbWVzc2FnZSA9IEVSUk9SX1JFU1BPTlNFU1tkYXRhLmVycm9yXSB8fFxyXG4gICAgZGF0YS5lcnJvciB8fFxyXG4gICAgZGF0YS5lcnJvcl9tZXNzYWdlXHJcblxyXG4gIC8vIFJldHVybiBhbiBlcnJvciBpbnN0YW5jZSB3aXRoIHRoZSBtZXNzYWdlIGlmIGl0IGV4aXN0cy5cclxuICByZXR1cm4gbWVzc2FnZSAmJiBuZXcgRXJyb3IobWVzc2FnZSlcclxufVxyXG5cclxuLyoqXHJcbiAqIEhhbmRsZSB0aGUgYXV0aGVudGljYXRpb24gcmVzcG9uc2Ugb2JqZWN0LlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXNcclxuICogQHJldHVybiB7UHJvbWlzZX1cclxuICovXHJcbmZ1bmN0aW9uIGhhbmRsZUF1dGhSZXNwb25zZSAocmVzKSB7XHJcbiAgdmFyIGRhdGEgPSByZXMuYm9keTtcclxuICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpO1xyXG5cclxuICAvLyBJZiB0aGUgcmVzcG9uc2UgY29udGFpbnMgYW4gZXJyb3IsIHJlamVjdCB0aGUgcmVmcmVzaCB0b2tlbi5cclxuICBpZiAoZXJyKSB7XHJcbiAgICByZXR1cm4gZXJyO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIGRhdGE7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTYW5pdGl6ZSB0aGUgc2NvcGVzIG9wdGlvbiB0byBiZSBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7QXJyYXl9ICBzY29wZXNcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc2FuaXRpemVTY29wZSAoc2NvcGVzKSB7XHJcbiAgcmV0dXJuIEFycmF5LmlzQXJyYXkoc2NvcGVzKSA/IHNjb3Blcy5qb2luKCcgJykgOiBzdHJpbmcoc2NvcGVzKTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBhIHJlcXVlc3QgdXJpIGJhc2VkIG9uIGFuIG9wdGlvbnMgb2JqZWN0IGFuZCB0b2tlbiB0eXBlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9IG9wdGlvbnNcclxuICogQHBhcmFtICB7U3RyaW5nfSB0b2tlblR5cGVcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gY3JlYXRlVXJpIChvcHRpb25zLCB0b2tlblR5cGUpIHtcclxuICAvLyBDaGVjayB0aGUgcmVxdWlyZWQgcGFyYW1ldGVycyBhcmUgc2V0LlxyXG4gIGV4cGVjdHMob3B0aW9ucywgW1xyXG4gICAgJ2NsaWVudElkJyxcclxuICAgICdyZWRpcmVjdFVyaScsXHJcbiAgICAnYXV0aG9yaXphdGlvblVyaSdcclxuICBdKTtcclxuXHJcbiAgdmFyIGNsaWVudElkID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuY2xpZW50SWQpO1xyXG4gIHZhciByZWRpcmVjdFVyaSA9IGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLnJlZGlyZWN0VXJpKTtcclxuICB2YXIgc2NvcGVzID0gZW5jb2RlVVJJQ29tcG9uZW50KHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpKTtcclxuICB2YXIgdXJpID0gb3B0aW9ucy5hdXRob3JpemF0aW9uVXJpICsgJz9jbGllbnRfaWQ9JyArIGNsaWVudElkICtcclxuICAgICcmcmVkaXJlY3RfdXJpPScgKyByZWRpcmVjdFVyaSArXHJcbiAgICAnJnNjb3BlPScgKyBzY29wZXMgK1xyXG4gICAgJyZyZXNwb25zZV90eXBlPScgKyB0b2tlblR5cGU7XHJcblxyXG4gIGlmIChvcHRpb25zLnN0YXRlKSB7XHJcbiAgICB1cmkgKz0gJyZzdGF0ZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuc3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHVyaTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBiYXNpYyBhdXRoIGhlYWRlci5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSB1c2VybmFtZVxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHBhc3N3b3JkXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGF1dGggKHVzZXJuYW1lLCBwYXNzd29yZCkge1xyXG4gIHJldHVybiAnQmFzaWMgJyArIGJ0b2Eoc3RyaW5nKHVzZXJuYW1lKSArICc6JyArIHN0cmluZyhwYXNzd29yZCkpO1xyXG59XHJcblxyXG4vKipcclxuICogRW5zdXJlIGEgdmFsdWUgaXMgYSBzdHJpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gc3RyXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIHN0cmluZyAoc3RyKSB7XHJcbiAgcmV0dXJuIHN0ciA9PSBudWxsID8gJycgOiBTdHJpbmcoc3RyKTtcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBSZXF1ZXN0T3B0aW9ucyB7XHJcbiAgICBib2R5OiBhbnk7XHJcbiAgICBxdWVyeTogYW55O1xyXG4gICAgaGVhZGVyczogYW55O1xyXG4gICAgb3B0aW9uczogYW55O1xyXG4gICAgbWV0aG9kOiBzdHJpbmc7XHJcbiAgICB1cmw6IHN0cmluZztcclxufTtcclxuXHJcbi8qKlxyXG4gKiBNZXJnZSByZXF1ZXN0IG9wdGlvbnMgZnJvbSBhbiBvcHRpb25zIG9iamVjdC5cclxuICovXHJcbmZ1bmN0aW9uIHJlcXVlc3RPcHRpb25zIChyZXF1ZXN0T3B0aW9ucywgb3B0aW9ucyk6IFJlcXVlc3RPcHRpb25zIHtcclxuXHJcbiAgcmV0dXJuIGV4dGVuZChyZXF1ZXN0T3B0aW9ucywge1xyXG4gICAgYm9keTogZXh0ZW5kKG9wdGlvbnMuYm9keSwgcmVxdWVzdE9wdGlvbnMuYm9keSksXHJcbiAgICBxdWVyeTogZXh0ZW5kKG9wdGlvbnMucXVlcnksIHJlcXVlc3RPcHRpb25zLnF1ZXJ5KSxcclxuICAgIGhlYWRlcnM6IGV4dGVuZChvcHRpb25zLmhlYWRlcnMsIHJlcXVlc3RPcHRpb25zLmhlYWRlcnMpLFxyXG4gICAgb3B0aW9uczogZXh0ZW5kKG9wdGlvbnMub3B0aW9ucywgcmVxdWVzdE9wdGlvbnMub3B0aW9ucylcclxuICB9KTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENvbnN0cnVjdCBhbiBvYmplY3QgdGhhdCBjYW4gaGFuZGxlIHRoZSBtdWx0aXBsZSBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvcHRpb25zXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQ2xpZW50T0F1dGgyIHtcclxuICAgIC8vIGNvZGUgOiBDb2RlRmxvdztcclxuICAgICB0b2tlbiA6IFRva2VuRmxvdztcclxuICAgIC8vIG93bmVyIDogT3duZXJGbG93O1xyXG4gICAgLy8gY3JlZGVudGlhbHMgOiBDcmVkZW50aWFsc0Zsb3c7XHJcbiAgICAvLyBqd3QgOiBKd3RCZWFyZXJGbG93O1xyXG4gICAgb3B0aW9ucyA6YW55O1xyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihvcHRpb25zOiBhbnkpXHJcbiAgICB7XHJcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcclxuXHJcbiAgICAgICAgLy8gdGhpcy5jb2RlID0gbmV3IENvZGVGbG93KHRoaXMpO1xyXG4gICAgICAgIHRoaXMudG9rZW4gPSBuZXcgVG9rZW5GbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMub3duZXIgPSBuZXcgT3duZXJGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuY3JlZGVudGlhbHMgPSBuZXcgQ3JlZGVudGlhbHNGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuand0ID0gbmV3IEp3dEJlYXJlckZsb3codGhpcyk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBjcmVhdGVUb2tlbihhY2Nlc3M6IHN0cmluZywgcmVmcmVzaDogc3RyaW5nLCB0eXBlOiBzdHJpbmcsIGRhdGE6IGFueSlcclxuICAgIHtcclxuICAgICAgICB2YXIgb3B0aW9ucyA9IGV4dGVuZChcclxuICAgICAgICAgICAgZGF0YSxcclxuICAgICAgICAgICAgdHlwZW9mIGFjY2VzcyA9PT0gJ3N0cmluZycgPyB7IGFjY2Vzc190b2tlbjogYWNjZXNzIH0gOiBhY2Nlc3MsXHJcbiAgICAgICAgICAgIHR5cGVvZiByZWZyZXNoID09PSAnc3RyaW5nJyA/IHsgcmVmcmVzaF90b2tlbjogcmVmcmVzaCB9IDogcmVmcmVzaCxcclxuICAgICAgICAgICAgdHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnID8geyB0b2tlbl90eXBlOiB0eXBlIH0gOiB0eXBlXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLCBvcHRpb25zKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIF9yZXF1ZXN0KHJlcXVlc3RPYmplY3QgOiBSZXF1ZXN0T3B0aW9ucykgOmFueSBcclxuICAgIHtcclxuICAgICAgICBsZXQgcmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBoZWFkZXJzID0gcmVxdWVzdE9iamVjdC5oZWFkZXJzO1xyXG4gICAgICAgIGZvcihsZXQgaGVhZGVyIGluIGhlYWRlcnMpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoaGVhZGVyLCBoZWFkZXJzW2hlYWRlcl0pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICByZXF1ZXN0Lm9wZW4ocmVxdWVzdE9iamVjdC5tZXRob2QsIHJlcXVlc3RPYmplY3QudXJsLCBmYWxzZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5zZW5kKHJlcXVlc3RPYmplY3QuYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3QucmVzcG9uc2U7XHJcbiAgICAgICAgXHJcbiAgICAvLyAgIHJldHVybiB0aGlzLnJlcXVlc3QocmVxdWVzdE9iamVjdClcclxuICAgIC8vICAgICAudGhlbihmdW5jdGlvbiAocmVzKSB7XHJcbiAgICAvLyAgICAgICBpZiAocmVzLnN0YXR1cyA8IDIwMCB8fCByZXMuc3RhdHVzID49IDM5OSkge1xyXG4gICAgLy8gICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKCdIVFRQIHN0YXR1cyAnICsgcmVzLnN0YXR1cylcclxuICAgIC8vICAgICAgICAgZXJyLnN0YXR1cyA9IHJlcy5zdGF0dXNcclxuICAgIC8vICAgICAgICAgZXJyLmJvZHkgPSByZXMuYm9keVxyXG4gICAgLy8gICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgLy8gICAgICAgfVxyXG5cclxuICAgIC8vICAgICAgIHJldHVybiByZXNcclxuICAgIC8vICAgICB9KVxyXG4gICAgfVxyXG59XHJcblxyXG4vKipcclxuICogQWxpYXMgdGhlIHRva2VuIGNvbnN0cnVjdG9yLlxyXG4gKlxyXG4gKiBAdHlwZSB7RnVuY3Rpb259XHJcbiAqL1xyXG4vL0NsaWVudE9BdXRoMi5Ub2tlbiA9IENsaWVudE9BdXRoMlRva2VuXHJcblxyXG5cclxuLyoqXHJcbiAqIFVzaW5nIHRoZSBidWlsdC1pbiByZXF1ZXN0IG1ldGhvZCwgd2UnbGwgYXV0b21hdGljYWxseSBhdHRlbXB0IHRvIHBhcnNlXHJcbiAqIHRoZSByZXNwb25zZS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSAgcmVxdWVzdE9iamVjdFxyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuXHJcblxyXG4vLyAvKipcclxuLy8gICogU2V0IGBwb3BzaWNsZWAgYXMgdGhlIGRlZmF1bHQgcmVxdWVzdCBtZXRob2QuXHJcbi8vICAqL1xyXG4vLyBDbGllbnRPQXV0aDIucHJvdG90eXBlLnJlcXVlc3QgPSBwb3BzaWNsZS5yZXF1ZXN0XHJcblxyXG4vKipcclxuICogR2VuZXJhbCBwdXJwb3NlIGNsaWVudCB0b2tlbiBnZW5lcmF0b3IuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBjbGllbnRcclxuICogQHBhcmFtIHtPYmplY3R9IGRhdGFcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDJUb2tlblxyXG57IFxyXG4gICAgY2xpZW50IDpDbGllbnRPQXV0aDI7XHJcbiAgICBkYXRhIDphbnk7XHJcbiAgICB0b2tlblR5cGUgOnN0cmluZztcclxuICAgIGFjY2Vzc1Rva2VuIDpzdHJpbmc7XHJcbiAgICByZWZyZXNoVG9rZW4gOnN0cmluZztcclxuICAgIGV4cGlyZXMgOkRhdGU7XHJcbiAgICBpZGVudGl0eVRva2VuOiBzdHJpbmc7XHJcbiAgICBcclxuXHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCwgZGF0YSkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgICAgIHRoaXMuZGF0YSA9IGRhdGE7XHJcbiAgICAgICAgdGhpcy50b2tlblR5cGUgPSBkYXRhLnRva2VuX3R5cGUgJiYgZGF0YS50b2tlbl90eXBlLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgdGhpcy5hY2Nlc3NUb2tlbiA9IGRhdGEuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuID0gZGF0YS5yZWZyZXNoX3Rva2VuO1xyXG4gICAgICAgIHRoaXMuaWRlbnRpdHlUb2tlbiA9IGRhdGEuaWRfdG9rZW47XHJcblxyXG4gICAgICAgIHRoaXMuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIGV4cGlyZXNJbihkdXJhdGlvbilcclxuICAgIHtcclxuICAgICAgICBpZiAoIWlzTmFOKGR1cmF0aW9uKSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcy5zZXRTZWNvbmRzKHRoaXMuZXhwaXJlcy5nZXRTZWNvbmRzKCkgKyBkdXJhdGlvbik7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2VcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IHVuZGVmaW5lZDtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZXhwaXJlcztcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHNpZ24ocmVxdWVzdE9iamVjdCkge1xyXG4gICAgICAgIGlmICghdGhpcy5hY2Nlc3NUb2tlbikge1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1VuYWJsZSB0byBzaWduIHdpdGhvdXQgYWNjZXNzIHRva2VuJylcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycyB8fCB7fVxyXG5cclxuICAgICAgICBpZiAodGhpcy50b2tlblR5cGUgPT09ICdiZWFyZXInKSB7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5BdXRob3JpemF0aW9uID0gJ0JlYXJlciAnICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB2YXIgcGFydHMgPSByZXF1ZXN0T2JqZWN0LnVybC5zcGxpdCgnIycpO1xyXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSAnYWNjZXNzX3Rva2VuPScgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgICAgICB2YXIgdXJsID0gcGFydHNbMF0ucmVwbGFjZSgvWz8mXWFjY2Vzc190b2tlbj1bXiYjXS8sICcnKTtcclxuICAgICAgICAgICAgdmFyIGZyYWdtZW50ID0gcGFydHNbMV0gPyAnIycgKyBwYXJ0c1sxXSA6ICcnO1xyXG5cclxuICAgICAgICAgICAgLy8gUHJlcGVuZCB0aGUgY29ycmVjdCBxdWVyeSBzdHJpbmcgcGFyYW1ldGVyIHRvIHRoZSB1cmwuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QudXJsID0gdXJsICsgKHVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgKyB0b2tlbiArIGZyYWdtZW50O1xyXG5cclxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBhdm9pZCBzdG9yaW5nIHRoZSB1cmwgaW4gcHJveGllcywgc2luY2UgdGhlIGFjY2VzcyB0b2tlblxyXG4gICAgICAgICAgICAvLyBpcyBleHBvc2VkIGluIHRoZSBxdWVyeSBwYXJhbWV0ZXJzLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuUHJhZ21hID0gJ25vLXN0b3JlJztcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzWydDYWNoZS1Db250cm9sJ10gPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3RPYmplY3Q7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyByZXF1ZXN0KG9wdGlvbnMpIHtcclxuICAgICAgICBsZXQgcmVxdWVzdE9wdGlvbnNSZXN1bHQgPSByZXF1ZXN0T3B0aW9ucyh0aGlzLnNpZ24ob3B0aW9ucyksIHRoaXMuY2xpZW50Lm9wdGlvbnMpO1xyXG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9uc1Jlc3VsdCk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIHJlZnJlc2gob3B0aW9ucyk6YW55IHtcclxuICAgICAgICB2YXIgc2VsZiA9IHRoaXM7XHJcblxyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5yZWZyZXNoVG9rZW4pIHtcclxuICAgICAgICAgICAgcmV0dXJuIG5ldyBFcnJvcignTm8gcmVmcmVzaCB0b2tlbiBzZXQnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXNwb25zZSA9IHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuICAgICAgICAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4gICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcclxuICAgICAgICAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUywge1xyXG4gICAgICAgICAgICBBdXRob3JpemF0aW9uOiBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4gICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgYm9keToge1xyXG4gICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcclxuICAgICAgICAgICAgZ3JhbnRfdHlwZTogJ3JlZnJlc2hfdG9rZW4nXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9LCBvcHRpb25zKSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGJvZHkgPSBoYW5kbGVBdXRoUmVzcG9uc2UocmVzcG9uc2UpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIC8vVE9ETzogVHJhdGFyIHF1YW5kbyBleGNlcHRpb25cclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmV0b3JubyA9IChmdW5jdGlvbiAoZGF0YSkge1xyXG4gICAgICAgICAgICBzZWxmLmFjY2Vzc1Rva2VuID0gZGF0YS5hY2Nlc3NfdG9rZW47XHJcbiAgICAgICAgICAgIHNlbGYucmVmcmVzaFRva2VuID0gZGF0YS5yZWZyZXNoX3Rva2VuO1xyXG5cclxuICAgICAgICAgICAgc2VsZi5leHBpcmVzSW4oZGF0YS5leHBpcmVzX2luKTtcclxuXHJcbiAgICAgICAgICAgIHJldHVybiBzZWxmO1xyXG4gICAgICAgIH0pKGJvZHkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiByZXRvcm5vO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBnZXQgZXhwaXJlZCgpIDogYm9vbGVhblxyXG4gICAge1xyXG4gICAgICAgIGlmICh0aGlzLmV4cGlyZXMpIHtcclxuICAgICAgICAgICAgcmV0dXJuIERhdGUubm93KCkgPiB0aGlzLmV4cGlyZXMuZ2V0VGltZSgpXHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBcclxuICAgICAgICAgXHJcbiAgICBwdWJsaWMgZ2V0VXNlckluZm8oYWNjZXNzVG9rZW46IHN0cmluZykgOiBVc2VySW5mb1Jlc3BvbnNlXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgIHVybDogdGhpcy5jbGllbnQub3B0aW9ucy51c2VySW5mb1VyaSxcclxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxyXG4gICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgYWNjZXNzVG9rZW5cclxuICAgICAgICB9KVxyXG4gICAgICAgIH0sIHRoaXMuY2xpZW50Lm9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgdXNlckluZm9SZXNwb25zZSA9IG5ldyBVc2VySW5mb1Jlc3BvbnNlKHJlc3BvbnNlLnN1Yik7XHJcbiAgICAgICAgdXNlckluZm9SZXNwb25zZSA9IGV4dGVuZCh1c2VySW5mb1Jlc3BvbnNlLCByZXNwb25zZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHVzZXJJbmZvUmVzcG9uc2U7XHJcbiAgICB9XHJcbiAgICAgICAgXHJcbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IHJlc291cmNlIG93bmVyIHBhc3N3b3JkIGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4zXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIE93bmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIE1ha2UgYSByZXF1ZXN0IG9uIGJlaGFsZiBvZiB0aGUgdXNlciBjcmVkZW50aWFscyB0byBnZXQgYW4gYWNjZXMgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVzZXJuYW1lXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHBhc3N3b3JkXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBPd25lckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcclxuLy8gICAgICAgcGFzc3dvcmQ6IHBhc3N3b3JkLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAncGFzc3dvcmQnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLyoqXHJcbiAqIFN1cHBvcnQgaW1wbGljaXQgT0F1dGggMi4wIGdyYW50LlxyXG4gKlxyXG4gKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjJcclxuICpcclxuICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIFRva2VuRmxvdyBcclxue1xyXG4gICAgY2xpZW50OiBDbGllbnRPQXV0aDI7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZ2V0VXJpKG9wdGlvbnM/OmFueSkge1xyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIGNyZWF0ZVVyaShvcHRpb25zLCAndG9rZW4nKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0VG9rZW4odXJpLCBzdGF0ZT8sIG9wdGlvbnM/KSBcclxuICAgIHtcclxuICAgICAgICAvL29wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIC8vIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbiAgICAgICAgLy8gdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbiAgICAgICAgLy8gaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1Nob3VsZCBtYXRjaCByZWRpcmVjdCB1cmk6ICcgKyB1cmkpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gSWYgbm8gcXVlcnkgc3RyaW5nIG9yIGZyYWdtZW50IGV4aXN0cywgd2Ugd29uJ3QgYmUgYWJsZSB0byBwYXJzZVxyXG4gICAgICAgIC8vIC8vIGFueSB1c2VmdWwgaW5mb3JtYXRpb24gZnJvbSB0aGUgdXJpLlxyXG4gICAgICAgIC8vIGlmICghdXJsLmhhc2ggJiYgIXVybC5zZWFyY2gpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyBFeHRyYWN0IGRhdGEgZnJvbSBib3RoIHRoZSBmcmFnbWVudCBhbmQgcXVlcnkgc3RyaW5nLiBUaGUgZnJhZ21lbnQgaXMgbW9zdFxyXG4gICAgICAgIC8vIGltcG9ydGFudCwgYnV0IHRoZSBxdWVyeSBzdHJpbmcgaXMgYWxzbyB1c2VkIGJlY2F1c2Ugc29tZSBPQXV0aCAyLjBcclxuICAgICAgICAvLyBpbXBsZW1lbnRhdGlvbnMgKEluc3RhZ3JhbSkgaGF2ZSBhIGJ1ZyB3aGVyZSBzdGF0ZSBpcyBwYXNzZWQgdmlhIHF1ZXJ5LlxyXG4gICAgICAgIC8vIHZhciBkYXRhID0gZXh0ZW5kKFxyXG4gICAgICAgIC8vICAgICB1cmwucXVlcnkgPyBwYXJzZVF1ZXJ5KHVybC5xdWVyeSkgOiB7fSxcclxuICAgICAgICAvLyAgICAgdXJsLmhhc2ggPyBwYXJzZVF1ZXJ5KHVybC5oYXNoLnN1YnN0cigxKSkgOiB7fVxyXG4gICAgICAgIC8vIClcclxuXHJcbiAgICAgICAgLy8gdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKVxyXG5cclxuICAgICAgICAvLyAvLyBDaGVjayBpZiB0aGUgcXVlcnkgc3RyaW5nIHdhcyBwb3B1bGF0ZWQgd2l0aCBhIGtub3duIGVycm9yLlxyXG4gICAgICAgIC8vIGlmIChlcnIpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIHdoZXRoZXIgdGhlIHN0YXRlIG1hdGNoZXMuXHJcbiAgICAgICAgLy8gaWYgKHN0YXRlICE9IG51bGwgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6ICcgKyBkYXRhLnN0YXRlKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIGZ1bmN0aW9uIFBhcnNlYXJVcmwodXJsOiBzdHJpbmcpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBpZih1cmwuaW5kZXhPZignIycpICE9PSAtMSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJyMnKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB1cmwuc3Vic3RyKHVybC5pbmRleE9mKCc/JyksdXJsLmxlbmd0aCkucmVwbGFjZSgnPycsJycpLnJlcGxhY2UoJyMnLCcnKS5zcGxpdCgnJicpLnJlZHVjZShmdW5jdGlvbihzLGMpe3ZhciB0PWMuc3BsaXQoJz0nKTtzW3RbMF1dPXRbMV07cmV0dXJuIHM7fSx7fSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCB1cmxQYXJzZWFkYSA9IFBhcnNlYXJVcmwodXJpKTtcclxuXHJcbiAgICAgICAgbGV0IGRhdGEgPSB1cmxQYXJzZWFkYTtcclxuXHJcbiAgICAgICAgLy8gSW5pdGFsaXplIGEgbmV3IHRva2VuIGFuZCByZXR1cm4uXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLmNsaWVudCwgZGF0YSk7XHJcbiAgICB9XHJcbiAgIFxyXG59XHJcbiAgICBcclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIENsYWltYWJsZVxyXG57XHJcbiAgICBnZXRDbGFpbShjbGFpbU5hbWU6IHN0cmluZylcclxuICAgIHtcclxuICAgICAgICByZXR1cm4gKDxhbnk+dGhpcylbY2xhaW1OYW1lXTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIFVzZXJJbmZvUmVzcG9uc2UgZXh0ZW5kcyBDbGFpbWFibGVcclxue1xyXG4gICAgY29uc3RydWN0b3IocHVibGljIHN1YjpzdHJpbmcpIFxyXG4gICAge1xyXG4gICAgICAgIHN1cGVyKCk7XHJcbiAgICB9XHJcbn1cclxuICAgIFxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBjbGllbnQgY3JlZGVudGlhbHMgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjRcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gQ3JlZGVudGlhbHNGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgdGhlIGNsaWVudCBjcmVkZW50aWFscy5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDcmVkZW50aWFsc0Zsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdjbGllbnRJZCcsXHJcbi8vICAgICAnY2xpZW50U2VjcmV0JyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnY2xpZW50X2NyZWRlbnRpYWxzJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGF1dGhvcml6YXRpb24gY29kZSBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDb2RlRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdlbmVyYXRlIHRoZSB1cmkgZm9yIGRvaW5nIHRoZSBmaXJzdCByZWRpcmVjdC5cclxuLy8gICpcclxuLy8gICogQHJldHVybiB7U3RyaW5nfVxyXG4vLyAgKi9cclxuLy8gQ29kZUZsb3cucHJvdG90eXBlLmdldFVyaSA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICdjb2RlJylcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdldCB0aGUgY29kZSB0b2tlbiBmcm9tIHRoZSByZWRpcmVjdGVkIHVyaSBhbmQgbWFrZSBhbm90aGVyIHJlcXVlc3QgZm9yXHJcbi8vICAqIHRoZSB1c2VyIGFjY2VzcyB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgdXJpXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIFtzdGF0ZV1cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJpLCBzdGF0ZSwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ3JlZGlyZWN0VXJpJyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgdXJsID0gcGFyc2VVcmwodXJpKVxyXG4vLyAgIHZhciBleHBlY3RlZFVybCA9IHBhcnNlVXJsKG9wdGlvbnMucmVkaXJlY3RVcmkpXHJcblxyXG4vLyAgIGlmICh1cmwucGF0aG5hbWUgIT09IGV4cGVjdGVkVXJsLnBhdGhuYW1lKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoIXVybC5zZWFyY2gpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdVbmFibGUgdG8gcHJvY2VzcyB1cmk6ICcgKyB1cmkpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgdmFyIGRhdGEgPSBwYXJzZVF1ZXJ5KHVybC5xdWVyeSlcclxuLy8gICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4vLyAgIGlmIChlcnIpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoc3RhdGUgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdJbnZhbGlkIHN0YXRlOicgKyBkYXRhLnN0YXRlKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIC8vIENoZWNrIHdoZXRoZXIgdGhlIHJlc3BvbnNlIGNvZGUgaXMgc2V0LlxyXG4vLyAgIGlmICghZGF0YS5jb2RlKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignTWlzc2luZyBjb2RlLCB1bmFibGUgdG8gcmVxdWVzdCB0b2tlbicpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUyksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIGNvZGU6IGRhdGEuY29kZSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ2F1dGhvcml6YXRpb25fY29kZScsXHJcbi8vICAgICAgIHJlZGlyZWN0X3VyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcclxuLy8gICAgICAgY2xpZW50X2lkOiBvcHRpb25zLmNsaWVudElkLFxyXG4vLyAgICAgICBjbGllbnRfc2VjcmV0OiBvcHRpb25zLmNsaWVudFNlY3JldFxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IEpTT04gV2ViIFRva2VuIChKV1QpIEJlYXJlciBUb2tlbiBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL2RyYWZ0LWlldGYtb2F1dGgtand0LWJlYXJlci0xMiNzZWN0aW9uLTIuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBKd3RCZWFyZXJGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgYSBKV1QgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge3N0cmluZ30gdG9rZW4gQSBKV1QgdG9rZW4uXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gSnd0QmVhcmVyRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodG9rZW4sIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgaGVhZGVycyA9IGV4dGVuZChERUZBVUxUX0hFQURFUlMpXHJcblxyXG4vLyAgIC8vIEF1dGhlbnRpY2F0aW9uIG9mIHRoZSBjbGllbnQgaXMgb3B0aW9uYWwsIGFzIGRlc2NyaWJlZCBpblxyXG4vLyAgIC8vIFNlY3Rpb24gMy4yLjEgb2YgT0F1dGggMi4wIFtSRkM2NzQ5XVxyXG4vLyAgIGlmIChvcHRpb25zLmNsaWVudElkKSB7XHJcbi8vICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogaGVhZGVycyxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAndXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlcicsXHJcbi8vICAgICAgIGFzc2VydGlvbjogdG9rZW5cclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcbiJdfQ==
