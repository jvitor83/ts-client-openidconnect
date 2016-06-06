System.register([], function(exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    var __extends = (this && this.__extends) || function (d, b) {
        for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
    var hasOwnProperty, extend, DEFAULT_HEADERS, ERROR_RESPONSES, ClientOAuth2, ClientOAuth2Token, Flow, TokenFlow, Claimable, UserInfoResponse;
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
                    request.open(requestObject.method, requestObject.url, false);
                    var headers = requestObject.headers;
                    for (var header in headers) {
                        request.setRequestHeader(header, headers[header]);
                    }
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
                Object.defineProperty(ClientOAuth2Token.prototype, "accessTokenContent", {
                    get: function () {
                        var content = this._accessToken.split('.')[1];
                        var returnContent = JSON.parse(content);
                        return returnContent;
                    },
                    enumerable: true,
                    configurable: true
                });
                ClientOAuth2Token.prototype.isAccessTokenExpired = function () {
                    var accessTokenContent = this.accessTokenContent;
                    var accessTokenExp = accessTokenContent.exp;
                    var expired = accessTokenExp < Math.floor(Date.now() / 1000);
                    return expired;
                };
                Object.defineProperty(ClientOAuth2Token.prototype, "accessToken", {
                    get: function () {
                        if (this.expired || this.isAccessTokenExpired) {
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
                        throw 'No refresh token set';
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
                return ClientOAuth2Token;
            }());
            exports_1("ClientOAuth2Token", ClientOAuth2Token);
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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QUFNQyxDQU5xQyxTQUFTLEdBTTlDO1lBTkQsK0NBTUMsQ0FBQSIsImZpbGUiOiJDbGllbnQuanMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBpbXBvcnQgJ3h0ZW5kJztcclxuLy8gaW1wb3J0ICdwb3BzaWNsZSc7XHJcbi8vIGltcG9ydCAncXVlcnlzdHJpbmcnO1xyXG4vLyBpbXBvcnQgJ3VybCc7XHJcblxyXG52YXIgaGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xyXG5cclxudmFyIGV4dGVuZCA9IGZ1bmN0aW9uIGV4dGVuZCguLi5hcmdzOkFycmF5PGFueT4pOmFueSB7XHJcbiAgICB2YXIgdGFyZ2V0ID0ge31cclxuXHJcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICB2YXIgc291cmNlID0gYXJnc1tpXVxyXG5cclxuICAgICAgICBmb3IgKHZhciBrZXkgaW4gc291cmNlKSB7XHJcbiAgICAgICAgICAgIGlmIChoYXNPd25Qcm9wZXJ0eS5jYWxsKHNvdXJjZSwga2V5KSkge1xyXG4gICAgICAgICAgICAgICAgdGFyZ2V0W2tleV0gPSBzb3VyY2Vba2V5XVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0YXJnZXQ7XHJcbn1cclxuXHJcblxyXG5cclxuLy92YXIgcG9wc2ljbGUgIDphbnk7XHJcbi8vdmFyIHBhcnNlUXVlcnkgOmFueTtcclxuLy92YXIgcGFyc2VVcmwgIDphbnk7XHJcblxyXG4vLyB2YXIgZXh0ZW5kID0gcmVxdWlyZSgneHRlbmQnKVxyXG4vLyB2YXIgcG9wc2ljbGUgPSByZXF1aXJlKCdwb3BzaWNsZScpXHJcbi8vIHZhciBwYXJzZVF1ZXJ5ID0gcmVxdWlyZSgncXVlcnlzdHJpbmcnKS5wYXJzZVxyXG4vLyB2YXIgcGFyc2VVcmwgPSByZXF1aXJlKCd1cmwnKS5wYXJzZVxyXG5cclxuLy92YXIgYnRvYSA9IHR5cGVvZiBCdWZmZXIgPT09ICdmdW5jdGlvbicgPyBidG9hQnVmZmVyIDogd2luZG93LmJ0b2FcclxuXHJcbi8qKlxyXG4gKiBEZWZhdWx0IGhlYWRlcnMgZm9yIGV4ZWN1dGluZyBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgREVGQVVMVF9IRUFERVJTID0ge1xyXG4gICdBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbiwgYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcclxuICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxufVxyXG5cclxuLyoqXHJcbiAqIEZvcm1hdCBlcnJvciByZXNwb25zZSB0eXBlcyB0byByZWd1bGFyIHN0cmluZ3MgZm9yIGRpc3BsYXlpbmcgdG8gY2xpZW50cy5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xLjIuMVxyXG4gKlxyXG4gKiBAdHlwZSB7T2JqZWN0fVxyXG4gKi9cclxudmFyIEVSUk9SX1JFU1BPTlNFUyA9IHtcclxuICAnaW52YWxpZF9yZXF1ZXN0JzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0IGlzIG1pc3NpbmcgYSByZXF1aXJlZCBwYXJhbWV0ZXIsIGluY2x1ZGVzIGFuJyxcclxuICAgICdpbnZhbGlkIHBhcmFtZXRlciB2YWx1ZSwgaW5jbHVkZXMgYSBwYXJhbWV0ZXIgbW9yZSB0aGFuJyxcclxuICAgICdvbmNlLCBvciBpcyBvdGhlcndpc2UgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9jbGllbnQnOiBbXHJcbiAgICAnQ2xpZW50IGF1dGhlbnRpY2F0aW9uIGZhaWxlZCAoZS5nLiwgdW5rbm93biBjbGllbnQsIG5vJyxcclxuICAgICdjbGllbnQgYXV0aGVudGljYXRpb24gaW5jbHVkZWQsIG9yIHVuc3VwcG9ydGVkJyxcclxuICAgICdhdXRoZW50aWNhdGlvbiBtZXRob2QpLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9ncmFudCc6IFtcclxuICAgICdUaGUgcHJvdmlkZWQgYXV0aG9yaXphdGlvbiBncmFudCAoZS5nLiwgYXV0aG9yaXphdGlvbicsXHJcbiAgICAnY29kZSwgcmVzb3VyY2Ugb3duZXIgY3JlZGVudGlhbHMpIG9yIHJlZnJlc2ggdG9rZW4gaXMnLFxyXG4gICAgJ2ludmFsaWQsIGV4cGlyZWQsIHJldm9rZWQsIGRvZXMgbm90IG1hdGNoIHRoZSByZWRpcmVjdGlvbicsXHJcbiAgICAnVVJJIHVzZWQgaW4gdGhlIGF1dGhvcml6YXRpb24gcmVxdWVzdCwgb3Igd2FzIGlzc3VlZCB0bycsXHJcbiAgICAnYW5vdGhlciBjbGllbnQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bmF1dGhvcml6ZWRfY2xpZW50JzogW1xyXG4gICAgJ1RoZSBjbGllbnQgaXMgbm90IGF1dGhvcml6ZWQgdG8gcmVxdWVzdCBhbiBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlIHVzaW5nIHRoaXMgbWV0aG9kLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfZ3JhbnRfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBncmFudCB0eXBlIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlJyxcclxuICAgICdhdXRob3JpemF0aW9uIHNlcnZlci4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2FjY2Vzc19kZW5pZWQnOiBbXHJcbiAgICAnVGhlIHJlc291cmNlIG93bmVyIG9yIGF1dGhvcml6YXRpb24gc2VydmVyIGRlbmllZCB0aGUgcmVxdWVzdC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3Vuc3VwcG9ydGVkX3Jlc3BvbnNlX3R5cGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGRvZXMgbm90IHN1cHBvcnQgb2J0YWluaW5nJyxcclxuICAgICdhbiBhdXRob3JpemF0aW9uIGNvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX3Njb3BlJzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0ZWQgc2NvcGUgaXMgaW52YWxpZCwgdW5rbm93biwgb3IgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnc2VydmVyX2Vycm9yJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBlbmNvdW50ZXJlZCBhbiB1bmV4cGVjdGVkJyxcclxuICAgICdjb25kaXRpb24gdGhhdCBwcmV2ZW50ZWQgaXQgZnJvbSBmdWxmaWxsaW5nIHRoZSByZXF1ZXN0LicsXHJcbiAgICAnKFRoaXMgZXJyb3IgY29kZSBpcyBuZWVkZWQgYmVjYXVzZSBhIDUwMCBJbnRlcm5hbCBTZXJ2ZXInLFxyXG4gICAgJ0Vycm9yIEhUVFAgc3RhdHVzIGNvZGUgY2Fubm90IGJlIHJldHVybmVkIHRvIHRoZSBjbGllbnQnLFxyXG4gICAgJ3ZpYSBhbiBIVFRQIHJlZGlyZWN0LiknXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3RlbXBvcmFyaWx5X3VuYXZhaWxhYmxlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBpcyBjdXJyZW50bHkgdW5hYmxlIHRvIGhhbmRsZScsXHJcbiAgICAndGhlIHJlcXVlc3QgZHVlIHRvIGEgdGVtcG9yYXJ5IG92ZXJsb2FkaW5nIG9yIG1haW50ZW5hbmNlJyxcclxuICAgICdvZiB0aGUgc2VydmVyLidcclxuICBdLmpvaW4oJyAnKVxyXG59XHJcblxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGlmIHByb3BlcnRpZXMgZXhpc3Qgb24gYW4gb2JqZWN0IGFuZCB0aHJvdyB3aGVuIHRoZXkgYXJlbid0LlxyXG4gKlxyXG4gKiBAdGhyb3dzIHtUeXBlRXJyb3J9IElmIGFuIGV4cGVjdGVkIHByb3BlcnR5IGlzIG1pc3NpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcclxuICogQHBhcmFtIHtBcnJheX0gIHByb3BzXHJcbiAqL1xyXG5mdW5jdGlvbiBleHBlY3RzIChvYmosIHByb3BzKSB7XHJcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwcm9wcy5sZW5ndGg7IGkrKykge1xyXG4gICAgdmFyIHByb3AgPSBwcm9wc1tpXVxyXG5cclxuICAgIGlmIChvYmpbcHJvcF0gPT0gbnVsbCkge1xyXG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcIicgKyBwcm9wICsgJ1wiIHRvIGV4aXN0JylcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBQdWxsIGFuIGF1dGhlbnRpY2F0aW9uIGVycm9yIGZyb20gdGhlIHJlc3BvbnNlIGRhdGEuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gZGF0YVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBnZXRBdXRoRXJyb3IgKGRhdGEpIHtcclxuICB2YXIgbWVzc2FnZSA9IEVSUk9SX1JFU1BPTlNFU1tkYXRhLmVycm9yXSB8fFxyXG4gICAgZGF0YS5lcnJvciB8fFxyXG4gICAgZGF0YS5lcnJvcl9tZXNzYWdlXHJcblxyXG4gIC8vIFJldHVybiBhbiBlcnJvciBpbnN0YW5jZSB3aXRoIHRoZSBtZXNzYWdlIGlmIGl0IGV4aXN0cy5cclxuICByZXR1cm4gbWVzc2FnZSAmJiBuZXcgRXJyb3IobWVzc2FnZSlcclxufVxyXG5cclxuLyoqXHJcbiAqIEhhbmRsZSB0aGUgYXV0aGVudGljYXRpb24gcmVzcG9uc2Ugb2JqZWN0LlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXNcclxuICogQHJldHVybiB7UHJvbWlzZX1cclxuICovXHJcbmZ1bmN0aW9uIGhhbmRsZUF1dGhSZXNwb25zZSAocmVzKSB7XHJcbiAgdmFyIGRhdGEgPSByZXMuYm9keTtcclxuICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpO1xyXG5cclxuICAvLyBJZiB0aGUgcmVzcG9uc2UgY29udGFpbnMgYW4gZXJyb3IsIHJlamVjdCB0aGUgcmVmcmVzaCB0b2tlbi5cclxuICBpZiAoZXJyKSB7XHJcbiAgICByZXR1cm4gZXJyO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIGRhdGE7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTYW5pdGl6ZSB0aGUgc2NvcGVzIG9wdGlvbiB0byBiZSBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7QXJyYXl9ICBzY29wZXNcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc2FuaXRpemVTY29wZSAoc2NvcGVzKSB7XHJcbiAgcmV0dXJuIEFycmF5LmlzQXJyYXkoc2NvcGVzKSA/IHNjb3Blcy5qb2luKCcgJykgOiBzdHJpbmcoc2NvcGVzKTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBhIHJlcXVlc3QgdXJpIGJhc2VkIG9uIGFuIG9wdGlvbnMgb2JqZWN0IGFuZCB0b2tlbiB0eXBlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9IG9wdGlvbnNcclxuICogQHBhcmFtICB7U3RyaW5nfSB0b2tlblR5cGVcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gY3JlYXRlVXJpIChvcHRpb25zLCB0b2tlblR5cGUpIHtcclxuICAvLyBDaGVjayB0aGUgcmVxdWlyZWQgcGFyYW1ldGVycyBhcmUgc2V0LlxyXG4gIGV4cGVjdHMob3B0aW9ucywgW1xyXG4gICAgJ2NsaWVudElkJyxcclxuICAgICdyZWRpcmVjdFVyaScsXHJcbiAgICAnYXV0aG9yaXphdGlvblVyaSdcclxuICBdKTtcclxuXHJcbiAgdmFyIGNsaWVudElkID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuY2xpZW50SWQpO1xyXG4gIHZhciByZWRpcmVjdFVyaSA9IGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLnJlZGlyZWN0VXJpKTtcclxuICB2YXIgc2NvcGVzID0gZW5jb2RlVVJJQ29tcG9uZW50KHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpKTtcclxuICB2YXIgdXJpID0gb3B0aW9ucy5hdXRob3JpemF0aW9uVXJpICsgJz9jbGllbnRfaWQ9JyArIGNsaWVudElkICtcclxuICAgICcmcmVkaXJlY3RfdXJpPScgKyByZWRpcmVjdFVyaSArXHJcbiAgICAnJnNjb3BlPScgKyBzY29wZXMgK1xyXG4gICAgJyZyZXNwb25zZV90eXBlPScgKyB0b2tlblR5cGU7XHJcblxyXG4gIGlmIChvcHRpb25zLnN0YXRlKSB7XHJcbiAgICB1cmkgKz0gJyZzdGF0ZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuc3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHVyaTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBiYXNpYyBhdXRoIGhlYWRlci5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSB1c2VybmFtZVxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHBhc3N3b3JkXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGF1dGggKHVzZXJuYW1lLCBwYXNzd29yZCkge1xyXG4gIHJldHVybiAnQmFzaWMgJyArIGJ0b2Eoc3RyaW5nKHVzZXJuYW1lKSArICc6JyArIHN0cmluZyhwYXNzd29yZCkpO1xyXG59XHJcblxyXG4vKipcclxuICogRW5zdXJlIGEgdmFsdWUgaXMgYSBzdHJpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gc3RyXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIHN0cmluZyAoc3RyKSB7XHJcbiAgcmV0dXJuIHN0ciA9PSBudWxsID8gJycgOiBTdHJpbmcoc3RyKTtcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBSZXF1ZXN0T3B0aW9ucyB7XHJcbiAgICBib2R5OiBhbnk7XHJcbiAgICBxdWVyeTogYW55O1xyXG4gICAgaGVhZGVyczogYW55O1xyXG4gICAgb3B0aW9uczogYW55O1xyXG4gICAgbWV0aG9kOiBzdHJpbmc7XHJcbiAgICB1cmw6IHN0cmluZztcclxufTtcclxuXHJcbi8qKlxyXG4gKiBNZXJnZSByZXF1ZXN0IG9wdGlvbnMgZnJvbSBhbiBvcHRpb25zIG9iamVjdC5cclxuICovXHJcbmZ1bmN0aW9uIHJlcXVlc3RPcHRpb25zIChyZXF1ZXN0T3B0aW9ucywgb3B0aW9ucyk6IFJlcXVlc3RPcHRpb25zIHtcclxuXHJcbiAgcmV0dXJuIGV4dGVuZChyZXF1ZXN0T3B0aW9ucywge1xyXG4gICAgYm9keTogZXh0ZW5kKG9wdGlvbnMuYm9keSwgcmVxdWVzdE9wdGlvbnMuYm9keSksXHJcbiAgICBxdWVyeTogZXh0ZW5kKG9wdGlvbnMucXVlcnksIHJlcXVlc3RPcHRpb25zLnF1ZXJ5KSxcclxuICAgIGhlYWRlcnM6IGV4dGVuZChvcHRpb25zLmhlYWRlcnMsIHJlcXVlc3RPcHRpb25zLmhlYWRlcnMpLFxyXG4gICAgb3B0aW9uczogZXh0ZW5kKG9wdGlvbnMub3B0aW9ucywgcmVxdWVzdE9wdGlvbnMub3B0aW9ucylcclxuICB9KTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENvbnN0cnVjdCBhbiBvYmplY3QgdGhhdCBjYW4gaGFuZGxlIHRoZSBtdWx0aXBsZSBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvcHRpb25zXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQ2xpZW50T0F1dGgyIHtcclxuICAgIC8vIGNvZGUgOiBDb2RlRmxvdztcclxuICAgICB0b2tlbiA6IFRva2VuRmxvdztcclxuICAgIC8vIG93bmVyIDogT3duZXJGbG93O1xyXG4gICAgLy8gY3JlZGVudGlhbHMgOiBDcmVkZW50aWFsc0Zsb3c7XHJcbiAgICAvLyBqd3QgOiBKd3RCZWFyZXJGbG93O1xyXG4gICAgb3B0aW9ucyA6YW55O1xyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihvcHRpb25zOiBhbnkpXHJcbiAgICB7XHJcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcclxuXHJcbiAgICAgICAgLy8gdGhpcy5jb2RlID0gbmV3IENvZGVGbG93KHRoaXMpO1xyXG4gICAgICAgIHRoaXMudG9rZW4gPSBuZXcgVG9rZW5GbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMub3duZXIgPSBuZXcgT3duZXJGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuY3JlZGVudGlhbHMgPSBuZXcgQ3JlZGVudGlhbHNGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuand0ID0gbmV3IEp3dEJlYXJlckZsb3codGhpcyk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBjcmVhdGVUb2tlbihhY2Nlc3M6IHN0cmluZywgcmVmcmVzaDogc3RyaW5nLCB0eXBlOiBzdHJpbmcsIGRhdGE6IGFueSlcclxuICAgIHtcclxuICAgICAgICB2YXIgb3B0aW9ucyA9IGV4dGVuZChcclxuICAgICAgICAgICAgZGF0YSxcclxuICAgICAgICAgICAgdHlwZW9mIGFjY2VzcyA9PT0gJ3N0cmluZycgPyB7IGFjY2Vzc190b2tlbjogYWNjZXNzIH0gOiBhY2Nlc3MsXHJcbiAgICAgICAgICAgIHR5cGVvZiByZWZyZXNoID09PSAnc3RyaW5nJyA/IHsgcmVmcmVzaF90b2tlbjogcmVmcmVzaCB9IDogcmVmcmVzaCxcclxuICAgICAgICAgICAgdHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnID8geyB0b2tlbl90eXBlOiB0eXBlIH0gOiB0eXBlXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLCBvcHRpb25zKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIF9yZXF1ZXN0KHJlcXVlc3RPYmplY3QgOiBSZXF1ZXN0T3B0aW9ucykgOmFueSBcclxuICAgIHtcclxuICAgICAgICBsZXQgcmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJlcXVlc3Qub3BlbihyZXF1ZXN0T2JqZWN0Lm1ldGhvZCwgcmVxdWVzdE9iamVjdC51cmwsIGZhbHNlKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycztcclxuICAgICAgICBmb3IobGV0IGhlYWRlciBpbiBoZWFkZXJzKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKGhlYWRlciwgaGVhZGVyc1toZWFkZXJdKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5zZW5kKHJlcXVlc3RPYmplY3QuYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3QucmVzcG9uc2U7XHJcbiAgICAgICAgXHJcbiAgICAvLyAgIHJldHVybiB0aGlzLnJlcXVlc3QocmVxdWVzdE9iamVjdClcclxuICAgIC8vICAgICAudGhlbihmdW5jdGlvbiAocmVzKSB7XHJcbiAgICAvLyAgICAgICBpZiAocmVzLnN0YXR1cyA8IDIwMCB8fCByZXMuc3RhdHVzID49IDM5OSkge1xyXG4gICAgLy8gICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKCdIVFRQIHN0YXR1cyAnICsgcmVzLnN0YXR1cylcclxuICAgIC8vICAgICAgICAgZXJyLnN0YXR1cyA9IHJlcy5zdGF0dXNcclxuICAgIC8vICAgICAgICAgZXJyLmJvZHkgPSByZXMuYm9keVxyXG4gICAgLy8gICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgLy8gICAgICAgfVxyXG5cclxuICAgIC8vICAgICAgIHJldHVybiByZXNcclxuICAgIC8vICAgICB9KVxyXG4gICAgfVxyXG59XHJcblxyXG4vKipcclxuICogQWxpYXMgdGhlIHRva2VuIGNvbnN0cnVjdG9yLlxyXG4gKlxyXG4gKiBAdHlwZSB7RnVuY3Rpb259XHJcbiAqL1xyXG4vL0NsaWVudE9BdXRoMi5Ub2tlbiA9IENsaWVudE9BdXRoMlRva2VuXHJcblxyXG5cclxuLyoqXHJcbiAqIFVzaW5nIHRoZSBidWlsdC1pbiByZXF1ZXN0IG1ldGhvZCwgd2UnbGwgYXV0b21hdGljYWxseSBhdHRlbXB0IHRvIHBhcnNlXHJcbiAqIHRoZSByZXNwb25zZS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSAgcmVxdWVzdE9iamVjdFxyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuXHJcblxyXG4vLyAvKipcclxuLy8gICogU2V0IGBwb3BzaWNsZWAgYXMgdGhlIGRlZmF1bHQgcmVxdWVzdCBtZXRob2QuXHJcbi8vICAqL1xyXG4vLyBDbGllbnRPQXV0aDIucHJvdG90eXBlLnJlcXVlc3QgPSBwb3BzaWNsZS5yZXF1ZXN0XHJcblxyXG4vKipcclxuICogR2VuZXJhbCBwdXJwb3NlIGNsaWVudCB0b2tlbiBnZW5lcmF0b3IuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBjbGllbnRcclxuICogQHBhcmFtIHtPYmplY3R9IGRhdGFcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDJUb2tlblxyXG57IFxyXG4gICAgY2xpZW50IDpDbGllbnRPQXV0aDI7XHJcbiAgICBkYXRhIDphbnk7XHJcbiAgICB0b2tlblR5cGUgOnN0cmluZztcclxuICAgIHJlZnJlc2hUb2tlbiA6c3RyaW5nO1xyXG4gICAgZXhwaXJlcyA6RGF0ZTtcclxuICAgIGlkZW50aXR5VG9rZW46IHN0cmluZztcclxuICAgIFxyXG4gICAgX2FjY2Vzc1Rva2VuIDpzdHJpbmc7XHJcbiAgICBcclxuICAgIFxyXG4gICAgZ2V0IGFjY2Vzc1Rva2VuQ29udGVudCgpOiBhbnlcclxuICAgIHtcclxuICAgICAgICBsZXQgY29udGVudCA9IHRoaXMuX2FjY2Vzc1Rva2VuLnNwbGl0KCcuJylbMV07XHJcbiAgICAgICAgbGV0IHJldHVybkNvbnRlbnQgPSBKU09OLnBhcnNlKGNvbnRlbnQpO1xyXG4gICAgICAgIHJldHVybiByZXR1cm5Db250ZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwcml2YXRlIGlzQWNjZXNzVG9rZW5FeHBpcmVkKClcclxuICAgIHtcclxuICAgICAgICBsZXQgYWNjZXNzVG9rZW5Db250ZW50ID0gdGhpcy5hY2Nlc3NUb2tlbkNvbnRlbnQ7XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGFjY2Vzc1Rva2VuRXhwIDpudW1iZXIgPSBhY2Nlc3NUb2tlbkNvbnRlbnQuZXhwO1xyXG4gICAgICAgIGxldCBleHBpcmVkID0gYWNjZXNzVG9rZW5FeHAgPCBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gZXhwaXJlZDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgZ2V0IGFjY2Vzc1Rva2VuKCkgOnN0cmluZ1xyXG4gICAge1xyXG4gICAgICAgIGlmKHRoaXMuZXhwaXJlZCB8fCB0aGlzLmlzQWNjZXNzVG9rZW5FeHBpcmVkKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5fYWNjZXNzVG9rZW47XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHNldCBhY2Nlc3NUb2tlbih2YWx1ZTpzdHJpbmcpIFxyXG4gICAge1xyXG4gICAgICAgIHRoaXMuX2FjY2Vzc1Rva2VuID0gdmFsdWU7XHJcbiAgICB9XHJcbiAgICBcclxuXHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCwgZGF0YSkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgICAgIHRoaXMuZGF0YSA9IGRhdGE7XHJcbiAgICAgICAgdGhpcy50b2tlblR5cGUgPSBkYXRhLnRva2VuX3R5cGUgJiYgZGF0YS50b2tlbl90eXBlLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgdGhpcy5hY2Nlc3NUb2tlbiA9IGRhdGEuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuID0gZGF0YS5yZWZyZXNoX3Rva2VuO1xyXG4gICAgICAgIHRoaXMuaWRlbnRpdHlUb2tlbiA9IGRhdGEuaWRfdG9rZW47XHJcblxyXG4gICAgICAgIHRoaXMuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIGV4cGlyZXNJbihkdXJhdGlvbilcclxuICAgIHtcclxuICAgICAgICBpZiAoIWlzTmFOKGR1cmF0aW9uKSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcy5zZXRTZWNvbmRzKHRoaXMuZXhwaXJlcy5nZXRTZWNvbmRzKCkgKyBkdXJhdGlvbik7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2VcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMuZXhwaXJlcyA9IHVuZGVmaW5lZDtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZXhwaXJlcztcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHNpZ24ocmVxdWVzdE9iamVjdCkge1xyXG4gICAgICAgIGlmICghdGhpcy5hY2Nlc3NUb2tlbikge1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1VuYWJsZSB0byBzaWduIHdpdGhvdXQgYWNjZXNzIHRva2VuJylcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycyB8fCB7fVxyXG5cclxuICAgICAgICBpZiAodGhpcy50b2tlblR5cGUgPT09ICdiZWFyZXInKSB7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5BdXRob3JpemF0aW9uID0gJ0JlYXJlciAnICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB2YXIgcGFydHMgPSByZXF1ZXN0T2JqZWN0LnVybC5zcGxpdCgnIycpO1xyXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSAnYWNjZXNzX3Rva2VuPScgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgICAgICB2YXIgdXJsID0gcGFydHNbMF0ucmVwbGFjZSgvWz8mXWFjY2Vzc190b2tlbj1bXiYjXS8sICcnKTtcclxuICAgICAgICAgICAgdmFyIGZyYWdtZW50ID0gcGFydHNbMV0gPyAnIycgKyBwYXJ0c1sxXSA6ICcnO1xyXG5cclxuICAgICAgICAgICAgLy8gUHJlcGVuZCB0aGUgY29ycmVjdCBxdWVyeSBzdHJpbmcgcGFyYW1ldGVyIHRvIHRoZSB1cmwuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QudXJsID0gdXJsICsgKHVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgKyB0b2tlbiArIGZyYWdtZW50O1xyXG5cclxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBhdm9pZCBzdG9yaW5nIHRoZSB1cmwgaW4gcHJveGllcywgc2luY2UgdGhlIGFjY2VzcyB0b2tlblxyXG4gICAgICAgICAgICAvLyBpcyBleHBvc2VkIGluIHRoZSBxdWVyeSBwYXJhbWV0ZXJzLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuUHJhZ21hID0gJ25vLXN0b3JlJztcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzWydDYWNoZS1Db250cm9sJ10gPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3RPYmplY3Q7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyByZXF1ZXN0KG9wdGlvbnMpIHtcclxuICAgICAgICBsZXQgcmVxdWVzdE9wdGlvbnNSZXN1bHQgPSByZXF1ZXN0T3B0aW9ucyh0aGlzLnNpZ24ob3B0aW9ucyksIHRoaXMuY2xpZW50Lm9wdGlvbnMpO1xyXG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9uc1Jlc3VsdCk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIFxyXG4gICAgcHVibGljIHJlZnJlc2gob3B0aW9ucz8pOmFueSB7XHJcbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xyXG5cclxuICAgICAgICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpO1xyXG5cclxuICAgICAgICBpZiAoIXRoaXMucmVmcmVzaFRva2VuKSB7XHJcbiAgICAgICAgICAgIHRocm93ICdObyByZWZyZXNoIHRva2VuIHNldCc7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmVzcG9uc2UgPSB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbiAgICAgICAgICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuICAgICAgICAgICAgfSksXHJcbiAgICAgICAgICAgIGJvZHk6IHtcclxuICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXHJcbiAgICAgICAgICAgIGdyYW50X3R5cGU6ICdyZWZyZXNoX3Rva2VuJ1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSwgb3B0aW9ucykpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBib2R5ID0gaGFuZGxlQXV0aFJlc3BvbnNlKHJlc3BvbnNlKTtcclxuICAgICAgICBcclxuICAgICAgICAvL1RPRE86IFRyYXRhciBxdWFuZG8gZXhjZXB0aW9uXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJldG9ybm8gPSAoZnVuY3Rpb24gKGRhdGEpIHtcclxuICAgICAgICAgICAgc2VsZi5hY2Nlc3NUb2tlbiA9IGRhdGEuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgICAgICBzZWxmLnJlZnJlc2hUb2tlbiA9IGRhdGEucmVmcmVzaF90b2tlbjtcclxuXHJcbiAgICAgICAgICAgIHNlbGYuZXhwaXJlc0luKGRhdGEuZXhwaXJlc19pbik7XHJcblxyXG4gICAgICAgICAgICByZXR1cm4gc2VsZjtcclxuICAgICAgICB9KShib2R5KTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gcmV0b3JubztcclxuICAgIH1cclxuICAgIFxyXG4gICAgZ2V0IGV4cGlyZWQoKSA6IGJvb2xlYW5cclxuICAgIHtcclxuICAgICAgICBpZiAodGhpcy5leHBpcmVzKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBEYXRlLm5vdygpID4gdGhpcy5leHBpcmVzLmdldFRpbWUoKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgICAgICBcclxuXHJcbiAgICAgICAgXHJcbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IHJlc291cmNlIG93bmVyIHBhc3N3b3JkIGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4zXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIE93bmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIE1ha2UgYSByZXF1ZXN0IG9uIGJlaGFsZiBvZiB0aGUgdXNlciBjcmVkZW50aWFscyB0byBnZXQgYW4gYWNjZXMgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVzZXJuYW1lXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHBhc3N3b3JkXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBPd25lckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcclxuLy8gICAgICAgcGFzc3dvcmQ6IHBhc3N3b3JkLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAncGFzc3dvcmQnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEZsb3dcclxue1xyXG4gICAgY2xpZW50OiBDbGllbnRPQXV0aDI7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZ2V0VXNlckluZm8oYWNjZXNzVG9rZW46IHN0cmluZykgOiBVc2VySW5mb1Jlc3BvbnNlXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgIHVybDogdGhpcy5jbGllbnQub3B0aW9ucy51c2VySW5mb1VyaSxcclxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxyXG4gICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgYWNjZXNzVG9rZW5cclxuICAgICAgICB9KVxyXG4gICAgICAgIH0sIHRoaXMuY2xpZW50Lm9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmVzcG9uc2VKU09OID0gSlNPTi5wYXJzZShyZXNwb25zZSk7XHJcbiAgICAgICAgbGV0IHVzZXJJbmZvUmVzcG9uc2UgPSBuZXcgVXNlckluZm9SZXNwb25zZShyZXNwb25zZUpTT04uc3ViKTtcclxuICAgICAgICB1c2VySW5mb1Jlc3BvbnNlID0gZXh0ZW5kKHVzZXJJbmZvUmVzcG9uc2UsIHJlc3BvbnNlSlNPTik7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHVzZXJJbmZvUmVzcG9uc2U7XHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTdXBwb3J0IGltcGxpY2l0IE9BdXRoIDIuMCBncmFudC5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4yXHJcbiAqXHJcbiAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuICovXHJcbmV4cG9ydCBjbGFzcyBUb2tlbkZsb3cgZXh0ZW5kcyBGbG93XHJcbntcclxuICAgIHB1YmxpYyBnZXRVcmkob3B0aW9ucz86YW55KSB7XHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICd0b2tlbicpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRUb2tlbih1cmksIHN0YXRlPywgb3B0aW9ucz8pIFxyXG4gICAge1xyXG4gICAgICAgIC8vb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgLy8gdmFyIHVybCA9IHBhcnNlVXJsKHVyaSlcclxuICAgICAgICAvLyB2YXIgZXhwZWN0ZWRVcmwgPSBwYXJzZVVybChvcHRpb25zLnJlZGlyZWN0VXJpKVxyXG5cclxuICAgICAgICAvLyBpZiAodXJsLnBhdGhuYW1lICE9PSBleHBlY3RlZFVybC5wYXRobmFtZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyAvLyBJZiBubyBxdWVyeSBzdHJpbmcgb3IgZnJhZ21lbnQgZXhpc3RzLCB3ZSB3b24ndCBiZSBhYmxlIHRvIHBhcnNlXHJcbiAgICAgICAgLy8gLy8gYW55IHVzZWZ1bCBpbmZvcm1hdGlvbiBmcm9tIHRoZSB1cmkuXHJcbiAgICAgICAgLy8gaWYgKCF1cmwuaGFzaCAmJiAhdXJsLnNlYXJjaCkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignVW5hYmxlIHRvIHByb2Nlc3MgdXJpOiAnICsgdXJpKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIEV4dHJhY3QgZGF0YSBmcm9tIGJvdGggdGhlIGZyYWdtZW50IGFuZCBxdWVyeSBzdHJpbmcuIFRoZSBmcmFnbWVudCBpcyBtb3N0XHJcbiAgICAgICAgLy8gaW1wb3J0YW50LCBidXQgdGhlIHF1ZXJ5IHN0cmluZyBpcyBhbHNvIHVzZWQgYmVjYXVzZSBzb21lIE9BdXRoIDIuMFxyXG4gICAgICAgIC8vIGltcGxlbWVudGF0aW9ucyAoSW5zdGFncmFtKSBoYXZlIGEgYnVnIHdoZXJlIHN0YXRlIGlzIHBhc3NlZCB2aWEgcXVlcnkuXHJcbiAgICAgICAgLy8gdmFyIGRhdGEgPSBleHRlbmQoXHJcbiAgICAgICAgLy8gICAgIHVybC5xdWVyeSA/IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KSA6IHt9LFxyXG4gICAgICAgIC8vICAgICB1cmwuaGFzaCA/IHBhcnNlUXVlcnkodXJsLmhhc2guc3Vic3RyKDEpKSA6IHt9XHJcbiAgICAgICAgLy8gKVxyXG5cclxuICAgICAgICAvLyB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIGlmIHRoZSBxdWVyeSBzdHJpbmcgd2FzIHBvcHVsYXRlZCB3aXRoIGEga25vd24gZXJyb3IuXHJcbiAgICAgICAgLy8gaWYgKGVycikge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gQ2hlY2sgd2hldGhlciB0aGUgc3RhdGUgbWF0Y2hlcy5cclxuICAgICAgICAvLyBpZiAoc3RhdGUgIT0gbnVsbCAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignSW52YWxpZCBzdGF0ZTogJyArIGRhdGEuc3RhdGUpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgZnVuY3Rpb24gUGFyc2VhclVybCh1cmw6IHN0cmluZylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKHVybC5pbmRleE9mKCcjJykgIT09IC0xKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdXJsLnN1YnN0cih1cmwuaW5kZXhPZignIycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJz8nKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IHVybFBhcnNlYWRhID0gUGFyc2VhclVybCh1cmkpO1xyXG5cclxuICAgICAgICBsZXQgZGF0YSA9IHVybFBhcnNlYWRhO1xyXG5cclxuICAgICAgICAvLyBJbml0YWxpemUgYSBuZXcgdG9rZW4gYW5kIHJldHVybi5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMuY2xpZW50LCBkYXRhKTtcclxuICAgIH1cclxuICAgXHJcbn1cclxuICAgIFxyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQ2xhaW1hYmxlXHJcbntcclxuICAgIGdldENsYWltKGNsYWltTmFtZTogc3RyaW5nKVxyXG4gICAge1xyXG4gICAgICAgIHJldHVybiAoPGFueT50aGlzKVtjbGFpbU5hbWVdO1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgVXNlckluZm9SZXNwb25zZSBleHRlbmRzIENsYWltYWJsZVxyXG57XHJcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3ViOnN0cmluZykgXHJcbiAgICB7XHJcbiAgICAgICAgc3VwZXIoKTtcclxuICAgIH1cclxufVxyXG4gICAgXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGNsaWVudCBjcmVkZW50aWFscyBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuNFxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDcmVkZW50aWFsc0Zsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyB0aGUgY2xpZW50IGNyZWRlbnRpYWxzLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENyZWRlbnRpYWxzRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAob3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICdjbGllbnRfY3JlZGVudGlhbHMnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgYXV0aG9yaXphdGlvbiBjb2RlIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIENvZGVGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2VuZXJhdGUgdGhlIHVyaSBmb3IgZG9pbmcgdGhlIGZpcnN0IHJlZGlyZWN0LlxyXG4vLyAgKlxyXG4vLyAgKiBAcmV0dXJuIHtTdHJpbmd9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VXJpID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiBjcmVhdGVVcmkob3B0aW9ucywgJ2NvZGUnKVxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2V0IHRoZSBjb2RlIHRva2VuIGZyb20gdGhlIHJlZGlyZWN0ZWQgdXJpIGFuZCBtYWtlIGFub3RoZXIgcmVxdWVzdCBmb3JcclxuLy8gICogdGhlIHVzZXIgYWNjZXNzIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICB1cmlcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgW3N0YXRlXVxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENvZGVGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1cmksIHN0YXRlLCBvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbi8vICAgICAnY2xpZW50SWQnLFxyXG4vLyAgICAgJ2NsaWVudFNlY3JldCcsXHJcbi8vICAgICAncmVkaXJlY3RVcmknLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbi8vICAgdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbi8vICAgaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdTaG91bGQgbWF0Y2ggcmVkaXJlY3QgdXJpOiAnICsgdXJpKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmICghdXJsLnNlYXJjaCkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICB2YXIgZGF0YSA9IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KVxyXG4vLyAgIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSlcclxuXHJcbi8vICAgaWYgKGVycikge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmIChzdGF0ZSAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6JyArIGRhdGEuc3RhdGUpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgLy8gQ2hlY2sgd2hldGhlciB0aGUgcmVzcG9uc2UgY29kZSBpcyBzZXQuXHJcbi8vICAgaWYgKCFkYXRhLmNvZGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdNaXNzaW5nIGNvZGUsIHVuYWJsZSB0byByZXF1ZXN0IHRva2VuJykpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTKSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgY29kZTogZGF0YS5jb2RlLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnYXV0aG9yaXphdGlvbl9jb2RlJyxcclxuLy8gICAgICAgcmVkaXJlY3RfdXJpOiBvcHRpb25zLnJlZGlyZWN0VXJpLFxyXG4vLyAgICAgICBjbGllbnRfaWQ6IG9wdGlvbnMuY2xpZW50SWQsXHJcbi8vICAgICAgIGNsaWVudF9zZWNyZXQ6IG9wdGlvbnMuY2xpZW50U2VjcmV0XHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgSlNPTiBXZWIgVG9rZW4gKEpXVCkgQmVhcmVyIFRva2VuIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvZHJhZnQtaWV0Zi1vYXV0aC1qd3QtYmVhcmVyLTEyI3NlY3Rpb24tMi4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIEp3dEJlYXJlckZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyBhIEpXVCB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7c3RyaW5nfSB0b2tlbiBBIEpXVCB0b2tlbi5cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBKd3RCZWFyZXJGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh0b2tlbiwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciBoZWFkZXJzID0gZXh0ZW5kKERFRkFVTFRfSEVBREVSUylcclxuXHJcbi8vICAgLy8gQXV0aGVudGljYXRpb24gb2YgdGhlIGNsaWVudCBpcyBvcHRpb25hbCwgYXMgZGVzY3JpYmVkIGluXHJcbi8vICAgLy8gU2VjdGlvbiAzLjIuMSBvZiBPQXV0aCAyLjAgW1JGQzY3NDldXHJcbi8vICAgaWYgKG9wdGlvbnMuY2xpZW50SWQpIHtcclxuLy8gICAgIGhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBoZWFkZXJzLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICd1cm46aWV0ZjpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTpqd3QtYmVhcmVyJyxcclxuLy8gICAgICAgYXNzZXJ0aW9uOiB0b2tlblxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuIl19
