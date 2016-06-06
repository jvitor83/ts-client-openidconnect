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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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QUM7Z0JBQ0wsdUJBQUM7WUFBRCxDQU5BLEFBTUMsQ0FOcUMsU0FBUyxHQU05QztZQU5ELCtDQU1DLENBQUEiLCJmaWxlIjoiQ2xpZW50LmpzIiwic291cmNlc0NvbnRlbnQiOlsiLy8gaW1wb3J0ICd4dGVuZCc7XHJcbi8vIGltcG9ydCAncG9wc2ljbGUnO1xyXG4vLyBpbXBvcnQgJ3F1ZXJ5c3RyaW5nJztcclxuLy8gaW1wb3J0ICd1cmwnO1xyXG5cclxudmFyIGhhc093blByb3BlcnR5ID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eTtcclxuXHJcbnZhciBleHRlbmQgPSBmdW5jdGlvbiBleHRlbmQoLi4uYXJnczpBcnJheTxhbnk+KTphbnkge1xyXG4gICAgdmFyIHRhcmdldCA9IHt9XHJcblxyXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmdzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgdmFyIHNvdXJjZSA9IGFyZ3NbaV1cclxuXHJcbiAgICAgICAgZm9yICh2YXIga2V5IGluIHNvdXJjZSkge1xyXG4gICAgICAgICAgICBpZiAoaGFzT3duUHJvcGVydHkuY2FsbChzb3VyY2UsIGtleSkpIHtcclxuICAgICAgICAgICAgICAgIHRhcmdldFtrZXldID0gc291cmNlW2tleV1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGFyZ2V0O1xyXG59XHJcblxyXG5cclxuXHJcbi8vdmFyIHBvcHNpY2xlICA6YW55O1xyXG4vL3ZhciBwYXJzZVF1ZXJ5IDphbnk7XHJcbi8vdmFyIHBhcnNlVXJsICA6YW55O1xyXG5cclxuLy8gdmFyIGV4dGVuZCA9IHJlcXVpcmUoJ3h0ZW5kJylcclxuLy8gdmFyIHBvcHNpY2xlID0gcmVxdWlyZSgncG9wc2ljbGUnKVxyXG4vLyB2YXIgcGFyc2VRdWVyeSA9IHJlcXVpcmUoJ3F1ZXJ5c3RyaW5nJykucGFyc2VcclxuLy8gdmFyIHBhcnNlVXJsID0gcmVxdWlyZSgndXJsJykucGFyc2VcclxuXHJcbi8vdmFyIGJ0b2EgPSB0eXBlb2YgQnVmZmVyID09PSAnZnVuY3Rpb24nID8gYnRvYUJ1ZmZlciA6IHdpbmRvdy5idG9hXHJcblxyXG4vKipcclxuICogRGVmYXVsdCBoZWFkZXJzIGZvciBleGVjdXRpbmcgT0F1dGggMi4wIGZsb3dzLlxyXG4gKlxyXG4gKiBAdHlwZSB7T2JqZWN0fVxyXG4gKi9cclxudmFyIERFRkFVTFRfSEVBREVSUyA9IHtcclxuICAnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24sIGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcsXHJcbiAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbn1cclxuXHJcbi8qKlxyXG4gKiBGb3JtYXQgZXJyb3IgcmVzcG9uc2UgdHlwZXMgdG8gcmVndWxhciBzdHJpbmdzIGZvciBkaXNwbGF5aW5nIHRvIGNsaWVudHMuXHJcbiAqXHJcbiAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMS4yLjFcclxuICpcclxuICogQHR5cGUge09iamVjdH1cclxuICovXHJcbnZhciBFUlJPUl9SRVNQT05TRVMgPSB7XHJcbiAgJ2ludmFsaWRfcmVxdWVzdCc6IFtcclxuICAgICdUaGUgcmVxdWVzdCBpcyBtaXNzaW5nIGEgcmVxdWlyZWQgcGFyYW1ldGVyLCBpbmNsdWRlcyBhbicsXHJcbiAgICAnaW52YWxpZCBwYXJhbWV0ZXIgdmFsdWUsIGluY2x1ZGVzIGEgcGFyYW1ldGVyIG1vcmUgdGhhbicsXHJcbiAgICAnb25jZSwgb3IgaXMgb3RoZXJ3aXNlIG1hbGZvcm1lZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfY2xpZW50JzogW1xyXG4gICAgJ0NsaWVudCBhdXRoZW50aWNhdGlvbiBmYWlsZWQgKGUuZy4sIHVua25vd24gY2xpZW50LCBubycsXHJcbiAgICAnY2xpZW50IGF1dGhlbnRpY2F0aW9uIGluY2x1ZGVkLCBvciB1bnN1cHBvcnRlZCcsXHJcbiAgICAnYXV0aGVudGljYXRpb24gbWV0aG9kKS4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfZ3JhbnQnOiBbXHJcbiAgICAnVGhlIHByb3ZpZGVkIGF1dGhvcml6YXRpb24gZ3JhbnQgKGUuZy4sIGF1dGhvcml6YXRpb24nLFxyXG4gICAgJ2NvZGUsIHJlc291cmNlIG93bmVyIGNyZWRlbnRpYWxzKSBvciByZWZyZXNoIHRva2VuIGlzJyxcclxuICAgICdpbnZhbGlkLCBleHBpcmVkLCByZXZva2VkLCBkb2VzIG5vdCBtYXRjaCB0aGUgcmVkaXJlY3Rpb24nLFxyXG4gICAgJ1VSSSB1c2VkIGluIHRoZSBhdXRob3JpemF0aW9uIHJlcXVlc3QsIG9yIHdhcyBpc3N1ZWQgdG8nLFxyXG4gICAgJ2Fub3RoZXIgY2xpZW50LidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5hdXRob3JpemVkX2NsaWVudCc6IFtcclxuICAgICdUaGUgY2xpZW50IGlzIG5vdCBhdXRob3JpemVkIHRvIHJlcXVlc3QgYW4gYXV0aG9yaXphdGlvbicsXHJcbiAgICAnY29kZSB1c2luZyB0aGlzIG1ldGhvZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3Vuc3VwcG9ydGVkX2dyYW50X3R5cGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gZ3JhbnQgdHlwZSBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoZScsXHJcbiAgICAnYXV0aG9yaXphdGlvbiBzZXJ2ZXIuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdhY2Nlc3NfZGVuaWVkJzogW1xyXG4gICAgJ1RoZSByZXNvdXJjZSBvd25lciBvciBhdXRob3JpemF0aW9uIHNlcnZlciBkZW5pZWQgdGhlIHJlcXVlc3QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bnN1cHBvcnRlZF9yZXNwb25zZV90eXBlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBkb2VzIG5vdCBzdXBwb3J0IG9idGFpbmluZycsXHJcbiAgICAnYW4gYXV0aG9yaXphdGlvbiBjb2RlIHVzaW5nIHRoaXMgbWV0aG9kLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9zY29wZSc6IFtcclxuICAgICdUaGUgcmVxdWVzdGVkIHNjb3BlIGlzIGludmFsaWQsIHVua25vd24sIG9yIG1hbGZvcm1lZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3NlcnZlcl9lcnJvcic6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZW5jb3VudGVyZWQgYW4gdW5leHBlY3RlZCcsXHJcbiAgICAnY29uZGl0aW9uIHRoYXQgcHJldmVudGVkIGl0IGZyb20gZnVsZmlsbGluZyB0aGUgcmVxdWVzdC4nLFxyXG4gICAgJyhUaGlzIGVycm9yIGNvZGUgaXMgbmVlZGVkIGJlY2F1c2UgYSA1MDAgSW50ZXJuYWwgU2VydmVyJyxcclxuICAgICdFcnJvciBIVFRQIHN0YXR1cyBjb2RlIGNhbm5vdCBiZSByZXR1cm5lZCB0byB0aGUgY2xpZW50JyxcclxuICAgICd2aWEgYW4gSFRUUCByZWRpcmVjdC4pJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd0ZW1wb3JhcmlseV91bmF2YWlsYWJsZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgaXMgY3VycmVudGx5IHVuYWJsZSB0byBoYW5kbGUnLFxyXG4gICAgJ3RoZSByZXF1ZXN0IGR1ZSB0byBhIHRlbXBvcmFyeSBvdmVybG9hZGluZyBvciBtYWludGVuYW5jZScsXHJcbiAgICAnb2YgdGhlIHNlcnZlci4nXHJcbiAgXS5qb2luKCcgJylcclxufVxyXG5cclxuXHJcbi8qKlxyXG4gKiBDaGVjayBpZiBwcm9wZXJ0aWVzIGV4aXN0IG9uIGFuIG9iamVjdCBhbmQgdGhyb3cgd2hlbiB0aGV5IGFyZW4ndC5cclxuICpcclxuICogQHRocm93cyB7VHlwZUVycm9yfSBJZiBhbiBleHBlY3RlZCBwcm9wZXJ0eSBpcyBtaXNzaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqXHJcbiAqIEBwYXJhbSB7QXJyYXl9ICBwcm9wc1xyXG4gKi9cclxuZnVuY3Rpb24gZXhwZWN0cyAob2JqLCBwcm9wcykge1xyXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcHJvcHMubGVuZ3RoOyBpKyspIHtcclxuICAgIHZhciBwcm9wID0gcHJvcHNbaV1cclxuXHJcbiAgICBpZiAob2JqW3Byb3BdID09IG51bGwpIHtcclxuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCInICsgcHJvcCArICdcIiB0byBleGlzdCcpXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG4vKipcclxuICogUHVsbCBhbiBhdXRoZW50aWNhdGlvbiBlcnJvciBmcm9tIHRoZSByZXNwb25zZSBkYXRhLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9IGRhdGFcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gZ2V0QXV0aEVycm9yIChkYXRhKSB7XHJcbiAgdmFyIG1lc3NhZ2UgPSBFUlJPUl9SRVNQT05TRVNbZGF0YS5lcnJvcl0gfHxcclxuICAgIGRhdGEuZXJyb3IgfHxcclxuICAgIGRhdGEuZXJyb3JfbWVzc2FnZVxyXG5cclxuICAvLyBSZXR1cm4gYW4gZXJyb3IgaW5zdGFuY2Ugd2l0aCB0aGUgbWVzc2FnZSBpZiBpdCBleGlzdHMuXHJcbiAgcmV0dXJuIG1lc3NhZ2UgJiYgbmV3IEVycm9yKG1lc3NhZ2UpXHJcbn1cclxuXHJcbi8qKlxyXG4gKiBIYW5kbGUgdGhlIGF1dGhlbnRpY2F0aW9uIHJlc3BvbnNlIG9iamVjdC5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSAgcmVzXHJcbiAqIEByZXR1cm4ge1Byb21pc2V9XHJcbiAqL1xyXG5mdW5jdGlvbiBoYW5kbGVBdXRoUmVzcG9uc2UgKHJlcykge1xyXG4gIHZhciBkYXRhID0gcmVzLmJvZHk7XHJcbiAgdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKTtcclxuXHJcbiAgLy8gSWYgdGhlIHJlc3BvbnNlIGNvbnRhaW5zIGFuIGVycm9yLCByZWplY3QgdGhlIHJlZnJlc2ggdG9rZW4uXHJcbiAgaWYgKGVycikge1xyXG4gICAgcmV0dXJuIGVycjtcclxuICB9XHJcblxyXG4gIHJldHVybiBkYXRhO1xyXG59XHJcblxyXG4vKipcclxuICogU2FuaXRpemUgdGhlIHNjb3BlcyBvcHRpb24gdG8gYmUgYSBzdHJpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSAge0FycmF5fSAgc2NvcGVzXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIHNhbml0aXplU2NvcGUgKHNjb3Blcykge1xyXG4gIHJldHVybiBBcnJheS5pc0FycmF5KHNjb3BlcykgPyBzY29wZXMuam9pbignICcpIDogc3RyaW5nKHNjb3Blcyk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDcmVhdGUgYSByZXF1ZXN0IHVyaSBiYXNlZCBvbiBhbiBvcHRpb25zIG9iamVjdCBhbmQgdG9rZW4gdHlwZS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSBvcHRpb25zXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gdG9rZW5UeXBlXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGNyZWF0ZVVyaSAob3B0aW9ucywgdG9rZW5UeXBlKSB7XHJcbiAgLy8gQ2hlY2sgdGhlIHJlcXVpcmVkIHBhcmFtZXRlcnMgYXJlIHNldC5cclxuICBleHBlY3RzKG9wdGlvbnMsIFtcclxuICAgICdjbGllbnRJZCcsXHJcbiAgICAncmVkaXJlY3RVcmknLFxyXG4gICAgJ2F1dGhvcml6YXRpb25VcmknXHJcbiAgXSk7XHJcblxyXG4gIHZhciBjbGllbnRJZCA9IGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLmNsaWVudElkKTtcclxuICB2YXIgcmVkaXJlY3RVcmkgPSBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5yZWRpcmVjdFVyaSk7XHJcbiAgdmFyIHNjb3BlcyA9IGVuY29kZVVSSUNvbXBvbmVudChzYW5pdGl6ZVNjb3BlKG9wdGlvbnMuc2NvcGVzKSk7XHJcbiAgdmFyIHVyaSA9IG9wdGlvbnMuYXV0aG9yaXphdGlvblVyaSArICc/Y2xpZW50X2lkPScgKyBjbGllbnRJZCArXHJcbiAgICAnJnJlZGlyZWN0X3VyaT0nICsgcmVkaXJlY3RVcmkgK1xyXG4gICAgJyZzY29wZT0nICsgc2NvcGVzICtcclxuICAgICcmcmVzcG9uc2VfdHlwZT0nICsgdG9rZW5UeXBlO1xyXG5cclxuICBpZiAob3B0aW9ucy5zdGF0ZSkge1xyXG4gICAgdXJpICs9ICcmc3RhdGU9JyArIGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLnN0YXRlKTtcclxuICB9XHJcblxyXG4gIHJldHVybiB1cmk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDcmVhdGUgYmFzaWMgYXV0aCBoZWFkZXIuXHJcbiAqXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gdXNlcm5hbWVcclxuICogQHBhcmFtICB7U3RyaW5nfSBwYXNzd29yZFxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBhdXRoICh1c2VybmFtZSwgcGFzc3dvcmQpIHtcclxuICByZXR1cm4gJ0Jhc2ljICcgKyBidG9hKHN0cmluZyh1c2VybmFtZSkgKyAnOicgKyBzdHJpbmcocGFzc3dvcmQpKTtcclxufVxyXG5cclxuLyoqXHJcbiAqIEVuc3VyZSBhIHZhbHVlIGlzIGEgc3RyaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHN0clxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBzdHJpbmcgKHN0cikge1xyXG4gIHJldHVybiBzdHIgPT0gbnVsbCA/ICcnIDogU3RyaW5nKHN0cik7XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgUmVxdWVzdE9wdGlvbnMge1xyXG4gICAgYm9keTogYW55O1xyXG4gICAgcXVlcnk6IGFueTtcclxuICAgIGhlYWRlcnM6IGFueTtcclxuICAgIG9wdGlvbnM6IGFueTtcclxuICAgIG1ldGhvZDogc3RyaW5nO1xyXG4gICAgdXJsOiBzdHJpbmc7XHJcbn07XHJcblxyXG4vKipcclxuICogTWVyZ2UgcmVxdWVzdCBvcHRpb25zIGZyb20gYW4gb3B0aW9ucyBvYmplY3QuXHJcbiAqL1xyXG5mdW5jdGlvbiByZXF1ZXN0T3B0aW9ucyAocmVxdWVzdE9wdGlvbnMsIG9wdGlvbnMpOiBSZXF1ZXN0T3B0aW9ucyB7XHJcblxyXG4gIHJldHVybiBleHRlbmQocmVxdWVzdE9wdGlvbnMsIHtcclxuICAgIGJvZHk6IGV4dGVuZChvcHRpb25zLmJvZHksIHJlcXVlc3RPcHRpb25zLmJvZHkpLFxyXG4gICAgcXVlcnk6IGV4dGVuZChvcHRpb25zLnF1ZXJ5LCByZXF1ZXN0T3B0aW9ucy5xdWVyeSksXHJcbiAgICBoZWFkZXJzOiBleHRlbmQob3B0aW9ucy5oZWFkZXJzLCByZXF1ZXN0T3B0aW9ucy5oZWFkZXJzKSxcclxuICAgIG9wdGlvbnM6IGV4dGVuZChvcHRpb25zLm9wdGlvbnMsIHJlcXVlc3RPcHRpb25zLm9wdGlvbnMpXHJcbiAgfSk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDb25zdHJ1Y3QgYW4gb2JqZWN0IHRoYXQgY2FuIGhhbmRsZSB0aGUgbXVsdGlwbGUgT0F1dGggMi4wIGZsb3dzLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9uc1xyXG4gKi9cclxuZXhwb3J0IGNsYXNzIENsaWVudE9BdXRoMiB7XHJcbiAgICAvLyBjb2RlIDogQ29kZUZsb3c7XHJcbiAgICAgdG9rZW4gOiBUb2tlbkZsb3c7XHJcbiAgICAvLyBvd25lciA6IE93bmVyRmxvdztcclxuICAgIC8vIGNyZWRlbnRpYWxzIDogQ3JlZGVudGlhbHNGbG93O1xyXG4gICAgLy8gand0IDogSnd0QmVhcmVyRmxvdztcclxuICAgIG9wdGlvbnMgOmFueTtcclxuICAgIFxyXG4gICAgY29uc3RydWN0b3Iob3B0aW9uczogYW55KVxyXG4gICAge1xyXG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XHJcblxyXG4gICAgICAgIC8vIHRoaXMuY29kZSA9IG5ldyBDb2RlRmxvdyh0aGlzKTtcclxuICAgICAgICB0aGlzLnRva2VuID0gbmV3IFRva2VuRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLm93bmVyID0gbmV3IE93bmVyRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLmNyZWRlbnRpYWxzID0gbmV3IENyZWRlbnRpYWxzRmxvdyh0aGlzKTtcclxuICAgICAgICAvLyB0aGlzLmp3dCA9IG5ldyBKd3RCZWFyZXJGbG93KHRoaXMpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgY3JlYXRlVG9rZW4oYWNjZXNzOiBzdHJpbmcsIHJlZnJlc2g6IHN0cmluZywgdHlwZTogc3RyaW5nLCBkYXRhOiBhbnkpXHJcbiAgICB7XHJcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBleHRlbmQoXHJcbiAgICAgICAgICAgIGRhdGEsXHJcbiAgICAgICAgICAgIHR5cGVvZiBhY2Nlc3MgPT09ICdzdHJpbmcnID8geyBhY2Nlc3NfdG9rZW46IGFjY2VzcyB9IDogYWNjZXNzLFxyXG4gICAgICAgICAgICB0eXBlb2YgcmVmcmVzaCA9PT0gJ3N0cmluZycgPyB7IHJlZnJlc2hfdG9rZW46IHJlZnJlc2ggfSA6IHJlZnJlc2gsXHJcbiAgICAgICAgICAgIHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJyA/IHsgdG9rZW5fdHlwZTogdHlwZSB9IDogdHlwZVxyXG4gICAgICAgICk7XHJcblxyXG4gICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4odGhpcywgb3B0aW9ucyk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBfcmVxdWVzdChyZXF1ZXN0T2JqZWN0IDogUmVxdWVzdE9wdGlvbnMpIDphbnkgXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcclxuICAgICAgICBcclxuICAgICAgICByZXF1ZXN0Lm9wZW4ocmVxdWVzdE9iamVjdC5tZXRob2QsIHJlcXVlc3RPYmplY3QudXJsLCBmYWxzZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGhlYWRlcnMgPSByZXF1ZXN0T2JqZWN0LmhlYWRlcnM7XHJcbiAgICAgICAgZm9yKGxldCBoZWFkZXIgaW4gaGVhZGVycylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihoZWFkZXIsIGhlYWRlcnNbaGVhZGVyXSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIHJlcXVlc3Quc2VuZChyZXF1ZXN0T2JqZWN0LmJvZHkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiByZXF1ZXN0LnJlc3BvbnNlO1xyXG4gICAgICAgIFxyXG4gICAgLy8gICByZXR1cm4gdGhpcy5yZXF1ZXN0KHJlcXVlc3RPYmplY3QpXHJcbiAgICAvLyAgICAgLnRoZW4oZnVuY3Rpb24gKHJlcykge1xyXG4gICAgLy8gICAgICAgaWYgKHJlcy5zdGF0dXMgPCAyMDAgfHwgcmVzLnN0YXR1cyA+PSAzOTkpIHtcclxuICAgIC8vICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcignSFRUUCBzdGF0dXMgJyArIHJlcy5zdGF0dXMpXHJcbiAgICAvLyAgICAgICAgIGVyci5zdGF0dXMgPSByZXMuc3RhdHVzXHJcbiAgICAvLyAgICAgICAgIGVyci5ib2R5ID0gcmVzLmJvZHlcclxuICAgIC8vICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgIC8vICAgICAgIH1cclxuXHJcbiAgICAvLyAgICAgICByZXR1cm4gcmVzXHJcbiAgICAvLyAgICAgfSlcclxuICAgIH1cclxufVxyXG5cclxuLyoqXHJcbiAqIEFsaWFzIHRoZSB0b2tlbiBjb25zdHJ1Y3Rvci5cclxuICpcclxuICogQHR5cGUge0Z1bmN0aW9ufVxyXG4gKi9cclxuLy9DbGllbnRPQXV0aDIuVG9rZW4gPSBDbGllbnRPQXV0aDJUb2tlblxyXG5cclxuXHJcbi8qKlxyXG4gKiBVc2luZyB0aGUgYnVpbHQtaW4gcmVxdWVzdCBtZXRob2QsIHdlJ2xsIGF1dG9tYXRpY2FsbHkgYXR0ZW1wdCB0byBwYXJzZVxyXG4gKiB0aGUgcmVzcG9uc2UuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gIHJlcXVlc3RPYmplY3RcclxuICogQHJldHVybiB7UHJvbWlzZX1cclxuICovXHJcblxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFNldCBgcG9wc2ljbGVgIGFzIHRoZSBkZWZhdWx0IHJlcXVlc3QgbWV0aG9kLlxyXG4vLyAgKi9cclxuLy8gQ2xpZW50T0F1dGgyLnByb3RvdHlwZS5yZXF1ZXN0ID0gcG9wc2ljbGUucmVxdWVzdFxyXG5cclxuLyoqXHJcbiAqIEdlbmVyYWwgcHVycG9zZSBjbGllbnQgdG9rZW4gZ2VuZXJhdG9yLlxyXG4gKlxyXG4gKiBAcGFyYW0ge09iamVjdH0gY2xpZW50XHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBkYXRhXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQ2xpZW50T0F1dGgyVG9rZW5cclxueyBcclxuICAgIGNsaWVudCA6Q2xpZW50T0F1dGgyO1xyXG4gICAgZGF0YSA6YW55O1xyXG4gICAgdG9rZW5UeXBlIDpzdHJpbmc7XHJcbiAgICByZWZyZXNoVG9rZW4gOnN0cmluZztcclxuICAgIGV4cGlyZXMgOkRhdGU7XHJcbiAgICBpZGVudGl0eVRva2VuOiBzdHJpbmc7XHJcbiAgICBcclxuICAgIF9hY2Nlc3NUb2tlbiA6c3RyaW5nO1xyXG4gICAgXHJcbiAgICBcclxuICAgIGdldCBhY2Nlc3NUb2tlbkNvbnRlbnQoKTogYW55XHJcbiAgICB7XHJcbiAgICAgICAgbGV0IGNvbnRlbnQgPSB0aGlzLl9hY2Nlc3NUb2tlbi5zcGxpdCgnLicpWzFdO1xyXG4gICAgICAgIGxldCByZXR1cm5Db250ZW50ID0gSlNPTi5wYXJzZShjb250ZW50KTtcclxuICAgICAgICByZXR1cm4gcmV0dXJuQ29udGVudDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHJpdmF0ZSBpc0FjY2Vzc1Rva2VuRXhwaXJlZCgpXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IGFjY2Vzc1Rva2VuQ29udGVudCA9IHRoaXMuYWNjZXNzVG9rZW5Db250ZW50O1xyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBhY2Nlc3NUb2tlbkV4cCA6bnVtYmVyID0gYWNjZXNzVG9rZW5Db250ZW50LmV4cDtcclxuICAgICAgICBsZXQgZXhwaXJlZCA9IGFjY2Vzc1Rva2VuRXhwIDwgTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIGV4cGlyZWQ7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGdldCBhY2Nlc3NUb2tlbigpIDpzdHJpbmdcclxuICAgIHtcclxuICAgICAgICBpZih0aGlzLmV4cGlyZWQgfHwgdGhpcy5pc0FjY2Vzc1Rva2VuRXhwaXJlZClcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaCgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY2Vzc1Rva2VuO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBzZXQgYWNjZXNzVG9rZW4odmFsdWU6c3RyaW5nKSBcclxuICAgIHtcclxuICAgICAgICB0aGlzLl9hY2Nlc3NUb2tlbiA9IHZhbHVlO1xyXG4gICAgfVxyXG4gICAgXHJcblxyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihjbGllbnQsIGRhdGEpIHtcclxuICAgICAgICB0aGlzLmNsaWVudCA9IGNsaWVudDtcclxuICAgICAgICB0aGlzLmRhdGEgPSBkYXRhO1xyXG4gICAgICAgIHRoaXMudG9rZW5UeXBlID0gZGF0YS50b2tlbl90eXBlICYmIGRhdGEudG9rZW5fdHlwZS50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICAgIHRoaXMuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbiA9IGRhdGEucmVmcmVzaF90b2tlbjtcclxuICAgICAgICB0aGlzLmlkZW50aXR5VG9rZW4gPSBkYXRhLmlkX3Rva2VuO1xyXG5cclxuICAgICAgICB0aGlzLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBcclxuICAgIHB1YmxpYyBleHBpcmVzSW4oZHVyYXRpb24pXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKCFpc05hTihkdXJhdGlvbikpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMuc2V0U2Vjb25kcyh0aGlzLmV4cGlyZXMuZ2V0U2Vjb25kcygpICsgZHVyYXRpb24pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBlbHNlXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMgPSB1bmRlZmluZWQ7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0aGlzLmV4cGlyZXM7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBzaWduKHJlcXVlc3RPYmplY3QpIHtcclxuICAgICAgICBpZiAoIXRoaXMuYWNjZXNzVG9rZW4pIHtcclxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gc2lnbiB3aXRob3V0IGFjY2VzcyB0b2tlbicpXHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMgPSByZXF1ZXN0T2JqZWN0LmhlYWRlcnMgfHwge31cclxuXHJcbiAgICAgICAgaWYgKHRoaXMudG9rZW5UeXBlID09PSAnYmVhcmVyJykge1xyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuQXV0aG9yaXphdGlvbiA9ICdCZWFyZXIgJyArIHRoaXMuYWNjZXNzVG9rZW47XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdmFyIHBhcnRzID0gcmVxdWVzdE9iamVjdC51cmwuc3BsaXQoJyMnKTtcclxuICAgICAgICAgICAgdmFyIHRva2VuID0gJ2FjY2Vzc190b2tlbj0nICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICAgICAgdmFyIHVybCA9IHBhcnRzWzBdLnJlcGxhY2UoL1s/Jl1hY2Nlc3NfdG9rZW49W14mI10vLCAnJyk7XHJcbiAgICAgICAgICAgIHZhciBmcmFnbWVudCA9IHBhcnRzWzFdID8gJyMnICsgcGFydHNbMV0gOiAnJztcclxuXHJcbiAgICAgICAgICAgIC8vIFByZXBlbmQgdGhlIGNvcnJlY3QgcXVlcnkgc3RyaW5nIHBhcmFtZXRlciB0byB0aGUgdXJsLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LnVybCA9IHVybCArICh1cmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPycpICsgdG9rZW4gKyBmcmFnbWVudDtcclxuXHJcbiAgICAgICAgICAgIC8vIEF0dGVtcHQgdG8gYXZvaWQgc3RvcmluZyB0aGUgdXJsIGluIHByb3hpZXMsIHNpbmNlIHRoZSBhY2Nlc3MgdG9rZW5cclxuICAgICAgICAgICAgLy8gaXMgZXhwb3NlZCBpbiB0aGUgcXVlcnkgcGFyYW1ldGVycy5cclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzLlByYWdtYSA9ICduby1zdG9yZSc7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVyc1snQ2FjaGUtQ29udHJvbCddID0gJ25vLXN0b3JlJztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiByZXF1ZXN0T2JqZWN0O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgcmVxdWVzdChvcHRpb25zKSB7XHJcbiAgICAgICAgbGV0IHJlcXVlc3RPcHRpb25zUmVzdWx0ID0gcmVxdWVzdE9wdGlvbnModGhpcy5zaWduKG9wdGlvbnMpLCB0aGlzLmNsaWVudC5vcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnNSZXN1bHQpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBcclxuICAgIHB1YmxpYyByZWZyZXNoKG9wdGlvbnM/KTphbnkge1xyXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcclxuXHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLnJlZnJlc2hUb2tlbikge1xyXG4gICAgICAgICAgICByZXR1cm4gbmV3IEVycm9yKCdObyByZWZyZXNoIHRva2VuIHNldCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4gICAgICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbiAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICBib2R5OiB7XHJcbiAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxyXG4gICAgICAgICAgICBncmFudF90eXBlOiAncmVmcmVzaF90b2tlbidcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0sIG9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBcclxuICAgICAgICBsZXQgYm9keSA9IGhhbmRsZUF1dGhSZXNwb25zZShyZXNwb25zZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgLy9UT0RPOiBUcmF0YXIgcXVhbmRvIGV4Y2VwdGlvblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXRvcm5vID0gKGZ1bmN0aW9uIChkYXRhKSB7XHJcbiAgICAgICAgICAgIHNlbGYuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICAgICAgc2VsZi5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcblxyXG4gICAgICAgICAgICBzZWxmLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHNlbGY7XHJcbiAgICAgICAgfSkoYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJldG9ybm87XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGdldCBleHBpcmVkKCkgOiBib29sZWFuXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKHRoaXMuZXhwaXJlcykge1xyXG4gICAgICAgICAgICByZXR1cm4gRGF0ZS5ub3coKSA+IHRoaXMuZXhwaXJlcy5nZXRUaW1lKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBcclxuICAgICAgICAgXHJcblxyXG4gICAgICAgIFxyXG59XHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcblxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCByZXNvdXJjZSBvd25lciBwYXNzd29yZCBjcmVkZW50aWFscyBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuM1xyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBPd25lckZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBNYWtlIGEgcmVxdWVzdCBvbiBiZWhhbGYgb2YgdGhlIHVzZXIgY3JlZGVudGlhbHMgdG8gZ2V0IGFuIGFjY2VzIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICB1c2VybmFtZVxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICBwYXNzd29yZFxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gT3duZXJGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1c2VybmFtZSwgcGFzc3dvcmQsIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICB1c2VybmFtZTogdXNlcm5hbWUsXHJcbi8vICAgICAgIHBhc3N3b3JkOiBwYXNzd29yZCxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ3Bhc3N3b3JkJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBGbG93XHJcbntcclxuICAgIGNsaWVudDogQ2xpZW50T0F1dGgyO1xyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihjbGllbnQpIHtcclxuICAgICAgICB0aGlzLmNsaWVudCA9IGNsaWVudDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIGdldFVzZXJJbmZvKGFjY2Vzc1Rva2VuOiBzdHJpbmcpIDogVXNlckluZm9SZXNwb25zZVxyXG4gICAge1xyXG4gICAgICAgIGxldCByZXNwb25zZSA9IHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuICAgICAgICB1cmw6IHRoaXMuY2xpZW50Lm9wdGlvbnMudXNlckluZm9VcmksXHJcbiAgICAgICAgbWV0aG9kOiAnR0VUJyxcclxuICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246ICdCZWFyZXIgJyArIGFjY2Vzc1Rva2VuXHJcbiAgICAgICAgfSlcclxuICAgICAgICB9LCB0aGlzLmNsaWVudC5vcHRpb25zKSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlSlNPTiA9IEpTT04ucGFyc2UocmVzcG9uc2UpO1xyXG4gICAgICAgIGxldCB1c2VySW5mb1Jlc3BvbnNlID0gbmV3IFVzZXJJbmZvUmVzcG9uc2UocmVzcG9uc2VKU09OLnN1Yik7XHJcbiAgICAgICAgdXNlckluZm9SZXNwb25zZSA9IGV4dGVuZCh1c2VySW5mb1Jlc3BvbnNlLCByZXNwb25zZUpTT04pO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiB1c2VySW5mb1Jlc3BvbnNlO1xyXG4gICAgfVxyXG59XHJcblxyXG4vKipcclxuICogU3VwcG9ydCBpbXBsaWNpdCBPQXV0aCAyLjAgZ3JhbnQuXHJcbiAqXHJcbiAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMlxyXG4gKlxyXG4gKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgVG9rZW5GbG93IGV4dGVuZHMgRmxvd1xyXG57XHJcbiAgICBwdWJsaWMgZ2V0VXJpKG9wdGlvbnM/OmFueSkge1xyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIGNyZWF0ZVVyaShvcHRpb25zLCAndG9rZW4nKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0VG9rZW4odXJpLCBzdGF0ZT8sIG9wdGlvbnM/KSBcclxuICAgIHtcclxuICAgICAgICAvL29wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIC8vIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbiAgICAgICAgLy8gdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbiAgICAgICAgLy8gaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1Nob3VsZCBtYXRjaCByZWRpcmVjdCB1cmk6ICcgKyB1cmkpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gSWYgbm8gcXVlcnkgc3RyaW5nIG9yIGZyYWdtZW50IGV4aXN0cywgd2Ugd29uJ3QgYmUgYWJsZSB0byBwYXJzZVxyXG4gICAgICAgIC8vIC8vIGFueSB1c2VmdWwgaW5mb3JtYXRpb24gZnJvbSB0aGUgdXJpLlxyXG4gICAgICAgIC8vIGlmICghdXJsLmhhc2ggJiYgIXVybC5zZWFyY2gpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyBFeHRyYWN0IGRhdGEgZnJvbSBib3RoIHRoZSBmcmFnbWVudCBhbmQgcXVlcnkgc3RyaW5nLiBUaGUgZnJhZ21lbnQgaXMgbW9zdFxyXG4gICAgICAgIC8vIGltcG9ydGFudCwgYnV0IHRoZSBxdWVyeSBzdHJpbmcgaXMgYWxzbyB1c2VkIGJlY2F1c2Ugc29tZSBPQXV0aCAyLjBcclxuICAgICAgICAvLyBpbXBsZW1lbnRhdGlvbnMgKEluc3RhZ3JhbSkgaGF2ZSBhIGJ1ZyB3aGVyZSBzdGF0ZSBpcyBwYXNzZWQgdmlhIHF1ZXJ5LlxyXG4gICAgICAgIC8vIHZhciBkYXRhID0gZXh0ZW5kKFxyXG4gICAgICAgIC8vICAgICB1cmwucXVlcnkgPyBwYXJzZVF1ZXJ5KHVybC5xdWVyeSkgOiB7fSxcclxuICAgICAgICAvLyAgICAgdXJsLmhhc2ggPyBwYXJzZVF1ZXJ5KHVybC5oYXNoLnN1YnN0cigxKSkgOiB7fVxyXG4gICAgICAgIC8vIClcclxuXHJcbiAgICAgICAgLy8gdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKVxyXG5cclxuICAgICAgICAvLyAvLyBDaGVjayBpZiB0aGUgcXVlcnkgc3RyaW5nIHdhcyBwb3B1bGF0ZWQgd2l0aCBhIGtub3duIGVycm9yLlxyXG4gICAgICAgIC8vIGlmIChlcnIpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIHdoZXRoZXIgdGhlIHN0YXRlIG1hdGNoZXMuXHJcbiAgICAgICAgLy8gaWYgKHN0YXRlICE9IG51bGwgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6ICcgKyBkYXRhLnN0YXRlKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIGZ1bmN0aW9uIFBhcnNlYXJVcmwodXJsOiBzdHJpbmcpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBpZih1cmwuaW5kZXhPZignIycpICE9PSAtMSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJyMnKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB1cmwuc3Vic3RyKHVybC5pbmRleE9mKCc/JyksdXJsLmxlbmd0aCkucmVwbGFjZSgnPycsJycpLnJlcGxhY2UoJyMnLCcnKS5zcGxpdCgnJicpLnJlZHVjZShmdW5jdGlvbihzLGMpe3ZhciB0PWMuc3BsaXQoJz0nKTtzW3RbMF1dPXRbMV07cmV0dXJuIHM7fSx7fSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCB1cmxQYXJzZWFkYSA9IFBhcnNlYXJVcmwodXJpKTtcclxuXHJcbiAgICAgICAgbGV0IGRhdGEgPSB1cmxQYXJzZWFkYTtcclxuXHJcbiAgICAgICAgLy8gSW5pdGFsaXplIGEgbmV3IHRva2VuIGFuZCByZXR1cm4uXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLmNsaWVudCwgZGF0YSk7XHJcbiAgICB9XHJcbiAgIFxyXG59XHJcbiAgICBcclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIENsYWltYWJsZVxyXG57XHJcbiAgICBnZXRDbGFpbShjbGFpbU5hbWU6IHN0cmluZylcclxuICAgIHtcclxuICAgICAgICByZXR1cm4gKDxhbnk+dGhpcylbY2xhaW1OYW1lXTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIFVzZXJJbmZvUmVzcG9uc2UgZXh0ZW5kcyBDbGFpbWFibGVcclxue1xyXG4gICAgY29uc3RydWN0b3IocHVibGljIHN1YjpzdHJpbmcpIFxyXG4gICAge1xyXG4gICAgICAgIHN1cGVyKCk7XHJcbiAgICB9XHJcbn1cclxuICAgIFxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBjbGllbnQgY3JlZGVudGlhbHMgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjRcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gQ3JlZGVudGlhbHNGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgdGhlIGNsaWVudCBjcmVkZW50aWFscy5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDcmVkZW50aWFsc0Zsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdjbGllbnRJZCcsXHJcbi8vICAgICAnY2xpZW50U2VjcmV0JyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnY2xpZW50X2NyZWRlbnRpYWxzJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGF1dGhvcml6YXRpb24gY29kZSBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDb2RlRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdlbmVyYXRlIHRoZSB1cmkgZm9yIGRvaW5nIHRoZSBmaXJzdCByZWRpcmVjdC5cclxuLy8gICpcclxuLy8gICogQHJldHVybiB7U3RyaW5nfVxyXG4vLyAgKi9cclxuLy8gQ29kZUZsb3cucHJvdG90eXBlLmdldFVyaSA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICdjb2RlJylcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdldCB0aGUgY29kZSB0b2tlbiBmcm9tIHRoZSByZWRpcmVjdGVkIHVyaSBhbmQgbWFrZSBhbm90aGVyIHJlcXVlc3QgZm9yXHJcbi8vICAqIHRoZSB1c2VyIGFjY2VzcyB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgdXJpXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIFtzdGF0ZV1cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJpLCBzdGF0ZSwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ3JlZGlyZWN0VXJpJyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgdXJsID0gcGFyc2VVcmwodXJpKVxyXG4vLyAgIHZhciBleHBlY3RlZFVybCA9IHBhcnNlVXJsKG9wdGlvbnMucmVkaXJlY3RVcmkpXHJcblxyXG4vLyAgIGlmICh1cmwucGF0aG5hbWUgIT09IGV4cGVjdGVkVXJsLnBhdGhuYW1lKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoIXVybC5zZWFyY2gpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdVbmFibGUgdG8gcHJvY2VzcyB1cmk6ICcgKyB1cmkpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgdmFyIGRhdGEgPSBwYXJzZVF1ZXJ5KHVybC5xdWVyeSlcclxuLy8gICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4vLyAgIGlmIChlcnIpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoc3RhdGUgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdJbnZhbGlkIHN0YXRlOicgKyBkYXRhLnN0YXRlKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIC8vIENoZWNrIHdoZXRoZXIgdGhlIHJlc3BvbnNlIGNvZGUgaXMgc2V0LlxyXG4vLyAgIGlmICghZGF0YS5jb2RlKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignTWlzc2luZyBjb2RlLCB1bmFibGUgdG8gcmVxdWVzdCB0b2tlbicpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUyksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIGNvZGU6IGRhdGEuY29kZSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ2F1dGhvcml6YXRpb25fY29kZScsXHJcbi8vICAgICAgIHJlZGlyZWN0X3VyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcclxuLy8gICAgICAgY2xpZW50X2lkOiBvcHRpb25zLmNsaWVudElkLFxyXG4vLyAgICAgICBjbGllbnRfc2VjcmV0OiBvcHRpb25zLmNsaWVudFNlY3JldFxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IEpTT04gV2ViIFRva2VuIChKV1QpIEJlYXJlciBUb2tlbiBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL2RyYWZ0LWlldGYtb2F1dGgtand0LWJlYXJlci0xMiNzZWN0aW9uLTIuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBKd3RCZWFyZXJGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgYSBKV1QgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge3N0cmluZ30gdG9rZW4gQSBKV1QgdG9rZW4uXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gSnd0QmVhcmVyRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodG9rZW4sIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgaGVhZGVycyA9IGV4dGVuZChERUZBVUxUX0hFQURFUlMpXHJcblxyXG4vLyAgIC8vIEF1dGhlbnRpY2F0aW9uIG9mIHRoZSBjbGllbnQgaXMgb3B0aW9uYWwsIGFzIGRlc2NyaWJlZCBpblxyXG4vLyAgIC8vIFNlY3Rpb24gMy4yLjEgb2YgT0F1dGggMi4wIFtSRkM2NzQ5XVxyXG4vLyAgIGlmIChvcHRpb25zLmNsaWVudElkKSB7XHJcbi8vICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogaGVhZGVycyxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAndXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlcicsXHJcbi8vICAgICAgIGFzc2VydGlvbjogdG9rZW5cclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcbiJdfQ==
