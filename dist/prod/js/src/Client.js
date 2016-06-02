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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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QUFNLENBQU8sSUFBSyxDQUFDLFNBQVMsQ0FBQyxDQUFDO2dCQUNsQyxDQUFDO2dCQUNMLGdCQUFDO1lBQUQsQ0FOQSxBQU1DLElBQUE7WUFORCxpQ0FNQyxDQUFBO1lBRUQ7Z0JBQXNDLG9DQUFTO2dCQUUzQywwQkFBbUIsR0FBVTtvQkFFekIsaUJBQU8sQ0FBQztvQkFGTyxRQUFHLEdBQUgsR0FBRyxDQUFPO2dCQUc3QixDQUFDO2dCQUNMLHVCQUFDO1lBQUQsQ0FOQSxBQU1DLENBTnFDLFNBQVMsR0FNOUM7WUFORCwrQ0FNQyxDQUFBIiwiZmlsZSI6IkNsaWVudC5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8vIGltcG9ydCAneHRlbmQnO1xyXG4vLyBpbXBvcnQgJ3BvcHNpY2xlJztcclxuLy8gaW1wb3J0ICdxdWVyeXN0cmluZyc7XHJcbi8vIGltcG9ydCAndXJsJztcclxuXHJcbnZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XHJcblxyXG52YXIgZXh0ZW5kID0gZnVuY3Rpb24gZXh0ZW5kKC4uLmFyZ3M6QXJyYXk8YW55Pik6YW55IHtcclxuICAgIHZhciB0YXJnZXQgPSB7fVxyXG5cclxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgIHZhciBzb3VyY2UgPSBhcmdzW2ldXHJcblxyXG4gICAgICAgIGZvciAodmFyIGtleSBpbiBzb3VyY2UpIHtcclxuICAgICAgICAgICAgaWYgKGhhc093blByb3BlcnR5LmNhbGwoc291cmNlLCBrZXkpKSB7XHJcbiAgICAgICAgICAgICAgICB0YXJnZXRba2V5XSA9IHNvdXJjZVtrZXldXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRhcmdldDtcclxufVxyXG5cclxuXHJcblxyXG4vL3ZhciBwb3BzaWNsZSAgOmFueTtcclxuLy92YXIgcGFyc2VRdWVyeSA6YW55O1xyXG4vL3ZhciBwYXJzZVVybCAgOmFueTtcclxuXHJcbi8vIHZhciBleHRlbmQgPSByZXF1aXJlKCd4dGVuZCcpXHJcbi8vIHZhciBwb3BzaWNsZSA9IHJlcXVpcmUoJ3BvcHNpY2xlJylcclxuLy8gdmFyIHBhcnNlUXVlcnkgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpLnBhcnNlXHJcbi8vIHZhciBwYXJzZVVybCA9IHJlcXVpcmUoJ3VybCcpLnBhcnNlXHJcblxyXG4vL3ZhciBidG9hID0gdHlwZW9mIEJ1ZmZlciA9PT0gJ2Z1bmN0aW9uJyA/IGJ0b2FCdWZmZXIgOiB3aW5kb3cuYnRvYVxyXG5cclxuLyoqXHJcbiAqIERlZmF1bHQgaGVhZGVycyBmb3IgZXhlY3V0aW5nIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHR5cGUge09iamVjdH1cclxuICovXHJcbnZhciBERUZBVUxUX0hFQURFUlMgPSB7XHJcbiAgJ0FjY2VwdCc6ICdhcHBsaWNhdGlvbi9qc29uLCBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnLFxyXG4gICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG59XHJcblxyXG4vKipcclxuICogRm9ybWF0IGVycm9yIHJlc3BvbnNlIHR5cGVzIHRvIHJlZ3VsYXIgc3RyaW5ncyBmb3IgZGlzcGxheWluZyB0byBjbGllbnRzLlxyXG4gKlxyXG4gKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjEuMi4xXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgRVJST1JfUkVTUE9OU0VTID0ge1xyXG4gICdpbnZhbGlkX3JlcXVlc3QnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3QgaXMgbWlzc2luZyBhIHJlcXVpcmVkIHBhcmFtZXRlciwgaW5jbHVkZXMgYW4nLFxyXG4gICAgJ2ludmFsaWQgcGFyYW1ldGVyIHZhbHVlLCBpbmNsdWRlcyBhIHBhcmFtZXRlciBtb3JlIHRoYW4nLFxyXG4gICAgJ29uY2UsIG9yIGlzIG90aGVyd2lzZSBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2NsaWVudCc6IFtcclxuICAgICdDbGllbnQgYXV0aGVudGljYXRpb24gZmFpbGVkIChlLmcuLCB1bmtub3duIGNsaWVudCwgbm8nLFxyXG4gICAgJ2NsaWVudCBhdXRoZW50aWNhdGlvbiBpbmNsdWRlZCwgb3IgdW5zdXBwb3J0ZWQnLFxyXG4gICAgJ2F1dGhlbnRpY2F0aW9uIG1ldGhvZCkuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX2dyYW50JzogW1xyXG4gICAgJ1RoZSBwcm92aWRlZCBhdXRob3JpemF0aW9uIGdyYW50IChlLmcuLCBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlLCByZXNvdXJjZSBvd25lciBjcmVkZW50aWFscykgb3IgcmVmcmVzaCB0b2tlbiBpcycsXHJcbiAgICAnaW52YWxpZCwgZXhwaXJlZCwgcmV2b2tlZCwgZG9lcyBub3QgbWF0Y2ggdGhlIHJlZGlyZWN0aW9uJyxcclxuICAgICdVUkkgdXNlZCBpbiB0aGUgYXV0aG9yaXphdGlvbiByZXF1ZXN0LCBvciB3YXMgaXNzdWVkIHRvJyxcclxuICAgICdhbm90aGVyIGNsaWVudC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3VuYXV0aG9yaXplZF9jbGllbnQnOiBbXHJcbiAgICAnVGhlIGNsaWVudCBpcyBub3QgYXV0aG9yaXplZCB0byByZXF1ZXN0IGFuIGF1dGhvcml6YXRpb24nLFxyXG4gICAgJ2NvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bnN1cHBvcnRlZF9ncmFudF90eXBlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIGdyYW50IHR5cGUgaXMgbm90IHN1cHBvcnRlZCBieSB0aGUnLFxyXG4gICAgJ2F1dGhvcml6YXRpb24gc2VydmVyLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnYWNjZXNzX2RlbmllZCc6IFtcclxuICAgICdUaGUgcmVzb3VyY2Ugb3duZXIgb3IgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZGVuaWVkIHRoZSByZXF1ZXN0LidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfcmVzcG9uc2VfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgZG9lcyBub3Qgc3VwcG9ydCBvYnRhaW5pbmcnLFxyXG4gICAgJ2FuIGF1dGhvcml6YXRpb24gY29kZSB1c2luZyB0aGlzIG1ldGhvZC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2ludmFsaWRfc2NvcGUnOiBbXHJcbiAgICAnVGhlIHJlcXVlc3RlZCBzY29wZSBpcyBpbnZhbGlkLCB1bmtub3duLCBvciBtYWxmb3JtZWQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdzZXJ2ZXJfZXJyb3InOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGVuY291bnRlcmVkIGFuIHVuZXhwZWN0ZWQnLFxyXG4gICAgJ2NvbmRpdGlvbiB0aGF0IHByZXZlbnRlZCBpdCBmcm9tIGZ1bGZpbGxpbmcgdGhlIHJlcXVlc3QuJyxcclxuICAgICcoVGhpcyBlcnJvciBjb2RlIGlzIG5lZWRlZCBiZWNhdXNlIGEgNTAwIEludGVybmFsIFNlcnZlcicsXHJcbiAgICAnRXJyb3IgSFRUUCBzdGF0dXMgY29kZSBjYW5ub3QgYmUgcmV0dXJuZWQgdG8gdGhlIGNsaWVudCcsXHJcbiAgICAndmlhIGFuIEhUVFAgcmVkaXJlY3QuKSdcclxuICBdLmpvaW4oJyAnKSxcclxuICAndGVtcG9yYXJpbHlfdW5hdmFpbGFibGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGlzIGN1cnJlbnRseSB1bmFibGUgdG8gaGFuZGxlJyxcclxuICAgICd0aGUgcmVxdWVzdCBkdWUgdG8gYSB0ZW1wb3Jhcnkgb3ZlcmxvYWRpbmcgb3IgbWFpbnRlbmFuY2UnLFxyXG4gICAgJ29mIHRoZSBzZXJ2ZXIuJ1xyXG4gIF0uam9pbignICcpXHJcbn1cclxuXHJcblxyXG4vKipcclxuICogQ2hlY2sgaWYgcHJvcGVydGllcyBleGlzdCBvbiBhbiBvYmplY3QgYW5kIHRocm93IHdoZW4gdGhleSBhcmVuJ3QuXHJcbiAqXHJcbiAqIEB0aHJvd3Mge1R5cGVFcnJvcn0gSWYgYW4gZXhwZWN0ZWQgcHJvcGVydHkgaXMgbWlzc2luZy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9ialxyXG4gKiBAcGFyYW0ge0FycmF5fSAgcHJvcHNcclxuICovXHJcbmZ1bmN0aW9uIGV4cGVjdHMgKG9iaiwgcHJvcHMpIHtcclxuICBmb3IgKHZhciBpID0gMDsgaSA8IHByb3BzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICB2YXIgcHJvcCA9IHByb3BzW2ldXHJcblxyXG4gICAgaWYgKG9ialtwcm9wXSA9PSBudWxsKSB7XHJcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiJyArIHByb3AgKyAnXCIgdG8gZXhpc3QnKVxyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuLyoqXHJcbiAqIFB1bGwgYW4gYXV0aGVudGljYXRpb24gZXJyb3IgZnJvbSB0aGUgcmVzcG9uc2UgZGF0YS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSBkYXRhXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGdldEF1dGhFcnJvciAoZGF0YSkge1xyXG4gIHZhciBtZXNzYWdlID0gRVJST1JfUkVTUE9OU0VTW2RhdGEuZXJyb3JdIHx8XHJcbiAgICBkYXRhLmVycm9yIHx8XHJcbiAgICBkYXRhLmVycm9yX21lc3NhZ2VcclxuXHJcbiAgLy8gUmV0dXJuIGFuIGVycm9yIGluc3RhbmNlIHdpdGggdGhlIG1lc3NhZ2UgaWYgaXQgZXhpc3RzLlxyXG4gIHJldHVybiBtZXNzYWdlICYmIG5ldyBFcnJvcihtZXNzYWdlKVxyXG59XHJcblxyXG4vKipcclxuICogSGFuZGxlIHRoZSBhdXRoZW50aWNhdGlvbiByZXNwb25zZSBvYmplY3QuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gIHJlc1xyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuZnVuY3Rpb24gaGFuZGxlQXV0aFJlc3BvbnNlIChyZXMpIHtcclxuICB2YXIgZGF0YSA9IHJlcy5ib2R5O1xyXG4gIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSk7XHJcblxyXG4gIC8vIElmIHRoZSByZXNwb25zZSBjb250YWlucyBhbiBlcnJvciwgcmVqZWN0IHRoZSByZWZyZXNoIHRva2VuLlxyXG4gIGlmIChlcnIpIHtcclxuICAgIHJldHVybiBlcnI7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZGF0YTtcclxufVxyXG5cclxuLyoqXHJcbiAqIFNhbml0aXplIHRoZSBzY29wZXMgb3B0aW9uIHRvIGJlIGEgc3RyaW5nLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtBcnJheX0gIHNjb3Blc1xyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBzYW5pdGl6ZVNjb3BlIChzY29wZXMpIHtcclxuICByZXR1cm4gQXJyYXkuaXNBcnJheShzY29wZXMpID8gc2NvcGVzLmpvaW4oJyAnKSA6IHN0cmluZyhzY29wZXMpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGEgcmVxdWVzdCB1cmkgYmFzZWQgb24gYW4gb3B0aW9ucyBvYmplY3QgYW5kIHRva2VuIHR5cGUuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gb3B0aW9uc1xyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHRva2VuVHlwZVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBjcmVhdGVVcmkgKG9wdGlvbnMsIHRva2VuVHlwZSkge1xyXG4gIC8vIENoZWNrIHRoZSByZXF1aXJlZCBwYXJhbWV0ZXJzIGFyZSBzZXQuXHJcbiAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbiAgICAnY2xpZW50SWQnLFxyXG4gICAgJ3JlZGlyZWN0VXJpJyxcclxuICAgICdhdXRob3JpemF0aW9uVXJpJ1xyXG4gIF0pO1xyXG5cclxuICB2YXIgY2xpZW50SWQgPSBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5jbGllbnRJZCk7XHJcbiAgdmFyIHJlZGlyZWN0VXJpID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMucmVkaXJlY3RVcmkpO1xyXG4gIHZhciBzY29wZXMgPSBlbmNvZGVVUklDb21wb25lbnQoc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcykpO1xyXG4gIHZhciB1cmkgPSBvcHRpb25zLmF1dGhvcml6YXRpb25VcmkgKyAnP2NsaWVudF9pZD0nICsgY2xpZW50SWQgK1xyXG4gICAgJyZyZWRpcmVjdF91cmk9JyArIHJlZGlyZWN0VXJpICtcclxuICAgICcmc2NvcGU9JyArIHNjb3BlcyArXHJcbiAgICAnJnJlc3BvbnNlX3R5cGU9JyArIHRva2VuVHlwZTtcclxuXHJcbiAgaWYgKG9wdGlvbnMuc3RhdGUpIHtcclxuICAgIHVyaSArPSAnJnN0YXRlPScgKyBlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5zdGF0ZSk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gdXJpO1xyXG59XHJcblxyXG4vKipcclxuICogQ3JlYXRlIGJhc2ljIGF1dGggaGVhZGVyLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHVzZXJuYW1lXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gcGFzc3dvcmRcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gYXV0aCAodXNlcm5hbWUsIHBhc3N3b3JkKSB7XHJcbiAgcmV0dXJuICdCYXNpYyAnICsgYnRvYShzdHJpbmcodXNlcm5hbWUpICsgJzonICsgc3RyaW5nKHBhc3N3b3JkKSk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBFbnN1cmUgYSB2YWx1ZSBpcyBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSBzdHJcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc3RyaW5nIChzdHIpIHtcclxuICByZXR1cm4gc3RyID09IG51bGwgPyAnJyA6IFN0cmluZyhzdHIpO1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFJlcXVlc3RPcHRpb25zIHtcclxuICAgIGJvZHk6IGFueTtcclxuICAgIHF1ZXJ5OiBhbnk7XHJcbiAgICBoZWFkZXJzOiBhbnk7XHJcbiAgICBvcHRpb25zOiBhbnk7XHJcbiAgICBtZXRob2Q6IHN0cmluZztcclxuICAgIHVybDogc3RyaW5nO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIE1lcmdlIHJlcXVlc3Qgb3B0aW9ucyBmcm9tIGFuIG9wdGlvbnMgb2JqZWN0LlxyXG4gKi9cclxuZnVuY3Rpb24gcmVxdWVzdE9wdGlvbnMgKHJlcXVlc3RPcHRpb25zLCBvcHRpb25zKTogUmVxdWVzdE9wdGlvbnMge1xyXG5cclxuICByZXR1cm4gZXh0ZW5kKHJlcXVlc3RPcHRpb25zLCB7XHJcbiAgICBib2R5OiBleHRlbmQob3B0aW9ucy5ib2R5LCByZXF1ZXN0T3B0aW9ucy5ib2R5KSxcclxuICAgIHF1ZXJ5OiBleHRlbmQob3B0aW9ucy5xdWVyeSwgcmVxdWVzdE9wdGlvbnMucXVlcnkpLFxyXG4gICAgaGVhZGVyczogZXh0ZW5kKG9wdGlvbnMuaGVhZGVycywgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXHJcbiAgICBvcHRpb25zOiBleHRlbmQob3B0aW9ucy5vcHRpb25zLCByZXF1ZXN0T3B0aW9ucy5vcHRpb25zKVxyXG4gIH0pO1xyXG59XHJcblxyXG4vKipcclxuICogQ29uc3RydWN0IGFuIG9iamVjdCB0aGF0IGNhbiBoYW5kbGUgdGhlIG11bHRpcGxlIE9BdXRoIDIuMCBmbG93cy5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDIge1xyXG4gICAgLy8gY29kZSA6IENvZGVGbG93O1xyXG4gICAgIHRva2VuIDogVG9rZW5GbG93O1xyXG4gICAgLy8gb3duZXIgOiBPd25lckZsb3c7XHJcbiAgICAvLyBjcmVkZW50aWFscyA6IENyZWRlbnRpYWxzRmxvdztcclxuICAgIC8vIGp3dCA6IEp3dEJlYXJlckZsb3c7XHJcbiAgICBvcHRpb25zIDphbnk7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKG9wdGlvbnM6IGFueSlcclxuICAgIHtcclxuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xyXG5cclxuICAgICAgICAvLyB0aGlzLmNvZGUgPSBuZXcgQ29kZUZsb3codGhpcyk7XHJcbiAgICAgICAgdGhpcy50b2tlbiA9IG5ldyBUb2tlbkZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5vd25lciA9IG5ldyBPd25lckZsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5jcmVkZW50aWFscyA9IG5ldyBDcmVkZW50aWFsc0Zsb3codGhpcyk7XHJcbiAgICAgICAgLy8gdGhpcy5qd3QgPSBuZXcgSnd0QmVhcmVyRmxvdyh0aGlzKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIGNyZWF0ZVRva2VuKGFjY2Vzczogc3RyaW5nLCByZWZyZXNoOiBzdHJpbmcsIHR5cGU6IHN0cmluZywgZGF0YTogYW55KVxyXG4gICAge1xyXG4gICAgICAgIHZhciBvcHRpb25zID0gZXh0ZW5kKFxyXG4gICAgICAgICAgICBkYXRhLFxyXG4gICAgICAgICAgICB0eXBlb2YgYWNjZXNzID09PSAnc3RyaW5nJyA/IHsgYWNjZXNzX3Rva2VuOiBhY2Nlc3MgfSA6IGFjY2VzcyxcclxuICAgICAgICAgICAgdHlwZW9mIHJlZnJlc2ggPT09ICdzdHJpbmcnID8geyByZWZyZXNoX3Rva2VuOiByZWZyZXNoIH0gOiByZWZyZXNoLFxyXG4gICAgICAgICAgICB0eXBlb2YgdHlwZSA9PT0gJ3N0cmluZycgPyB7IHRva2VuX3R5cGU6IHR5cGUgfSA6IHR5cGVcclxuICAgICAgICApO1xyXG5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMsIG9wdGlvbnMpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgX3JlcXVlc3QocmVxdWVzdE9iamVjdCA6IFJlcXVlc3RPcHRpb25zKSA6YW55IFxyXG4gICAge1xyXG4gICAgICAgIGxldCByZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5vcGVuKHJlcXVlc3RPYmplY3QubWV0aG9kLCByZXF1ZXN0T2JqZWN0LnVybCwgZmFsc2UpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBoZWFkZXJzID0gcmVxdWVzdE9iamVjdC5oZWFkZXJzO1xyXG4gICAgICAgIGZvcihsZXQgaGVhZGVyIGluIGhlYWRlcnMpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoaGVhZGVyLCBoZWFkZXJzW2hlYWRlcl0pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICByZXF1ZXN0LnNlbmQocmVxdWVzdE9iamVjdC5ib2R5KTtcclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gcmVxdWVzdC5yZXNwb25zZTtcclxuICAgICAgICBcclxuICAgIC8vICAgcmV0dXJuIHRoaXMucmVxdWVzdChyZXF1ZXN0T2JqZWN0KVxyXG4gICAgLy8gICAgIC50aGVuKGZ1bmN0aW9uIChyZXMpIHtcclxuICAgIC8vICAgICAgIGlmIChyZXMuc3RhdHVzIDwgMjAwIHx8IHJlcy5zdGF0dXMgPj0gMzk5KSB7XHJcbiAgICAvLyAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoJ0hUVFAgc3RhdHVzICcgKyByZXMuc3RhdHVzKVxyXG4gICAgLy8gICAgICAgICBlcnIuc3RhdHVzID0gcmVzLnN0YXR1c1xyXG4gICAgLy8gICAgICAgICBlcnIuYm9keSA9IHJlcy5ib2R5XHJcbiAgICAvLyAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbiAgICAvLyAgICAgICB9XHJcblxyXG4gICAgLy8gICAgICAgcmV0dXJuIHJlc1xyXG4gICAgLy8gICAgIH0pXHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBBbGlhcyB0aGUgdG9rZW4gY29uc3RydWN0b3IuXHJcbiAqXHJcbiAqIEB0eXBlIHtGdW5jdGlvbn1cclxuICovXHJcbi8vQ2xpZW50T0F1dGgyLlRva2VuID0gQ2xpZW50T0F1dGgyVG9rZW5cclxuXHJcblxyXG4vKipcclxuICogVXNpbmcgdGhlIGJ1aWx0LWluIHJlcXVlc3QgbWV0aG9kLCB3ZSdsbCBhdXRvbWF0aWNhbGx5IGF0dGVtcHQgdG8gcGFyc2VcclxuICogdGhlIHJlc3BvbnNlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXF1ZXN0T2JqZWN0XHJcbiAqIEByZXR1cm4ge1Byb21pc2V9XHJcbiAqL1xyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTZXQgYHBvcHNpY2xlYCBhcyB0aGUgZGVmYXVsdCByZXF1ZXN0IG1ldGhvZC5cclxuLy8gICovXHJcbi8vIENsaWVudE9BdXRoMi5wcm90b3R5cGUucmVxdWVzdCA9IHBvcHNpY2xlLnJlcXVlc3RcclxuXHJcbi8qKlxyXG4gKiBHZW5lcmFsIHB1cnBvc2UgY2xpZW50IHRva2VuIGdlbmVyYXRvci5cclxuICpcclxuICogQHBhcmFtIHtPYmplY3R9IGNsaWVudFxyXG4gKiBAcGFyYW0ge09iamVjdH0gZGF0YVxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIENsaWVudE9BdXRoMlRva2VuXHJcbnsgXHJcbiAgICBjbGllbnQgOkNsaWVudE9BdXRoMjtcclxuICAgIGRhdGEgOmFueTtcclxuICAgIHRva2VuVHlwZSA6c3RyaW5nO1xyXG4gICAgYWNjZXNzVG9rZW4gOnN0cmluZztcclxuICAgIHJlZnJlc2hUb2tlbiA6c3RyaW5nO1xyXG4gICAgZXhwaXJlcyA6RGF0ZTtcclxuICAgIGlkZW50aXR5VG9rZW46IHN0cmluZztcclxuICAgIFxyXG5cclxuICAgIFxyXG4gICAgY29uc3RydWN0b3IoY2xpZW50LCBkYXRhKSB7XHJcbiAgICAgICAgdGhpcy5jbGllbnQgPSBjbGllbnQ7XHJcbiAgICAgICAgdGhpcy5kYXRhID0gZGF0YTtcclxuICAgICAgICB0aGlzLnRva2VuVHlwZSA9IGRhdGEudG9rZW5fdHlwZSAmJiBkYXRhLnRva2VuX3R5cGUudG9Mb3dlckNhc2UoKTtcclxuICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuID0gZGF0YS5hY2Nlc3NfdG9rZW47XHJcbiAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcbiAgICAgICAgdGhpcy5pZGVudGl0eVRva2VuID0gZGF0YS5pZF90b2tlbjtcclxuXHJcbiAgICAgICAgdGhpcy5leHBpcmVzSW4oZGF0YS5leHBpcmVzX2luKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgXHJcbiAgICBwdWJsaWMgZXhwaXJlc0luKGR1cmF0aW9uKVxyXG4gICAge1xyXG4gICAgICAgIGlmICghaXNOYU4oZHVyYXRpb24pKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzID0gbmV3IERhdGUoKTtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzLnNldFNlY29uZHModGhpcy5leHBpcmVzLmdldFNlY29uZHMoKSArIGR1cmF0aW9uKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZWxzZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5leHBpcmVzID0gdW5kZWZpbmVkO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdGhpcy5leHBpcmVzO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgc2lnbihyZXF1ZXN0T2JqZWN0KSB7XHJcbiAgICAgICAgaWYgKCF0aGlzLmFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignVW5hYmxlIHRvIHNpZ24gd2l0aG91dCBhY2Nlc3MgdG9rZW4nKVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzID0gcmVxdWVzdE9iamVjdC5oZWFkZXJzIHx8IHt9XHJcblxyXG4gICAgICAgIGlmICh0aGlzLnRva2VuVHlwZSA9PT0gJ2JlYXJlcicpIHtcclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzLkF1dGhvcml6YXRpb24gPSAnQmVhcmVyICcgKyB0aGlzLmFjY2Vzc1Rva2VuO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIHZhciBwYXJ0cyA9IHJlcXVlc3RPYmplY3QudXJsLnNwbGl0KCcjJyk7XHJcbiAgICAgICAgICAgIHZhciB0b2tlbiA9ICdhY2Nlc3NfdG9rZW49JyArIHRoaXMuYWNjZXNzVG9rZW47XHJcbiAgICAgICAgICAgIHZhciB1cmwgPSBwYXJ0c1swXS5yZXBsYWNlKC9bPyZdYWNjZXNzX3Rva2VuPVteJiNdLywgJycpO1xyXG4gICAgICAgICAgICB2YXIgZnJhZ21lbnQgPSBwYXJ0c1sxXSA/ICcjJyArIHBhcnRzWzFdIDogJyc7XHJcblxyXG4gICAgICAgICAgICAvLyBQcmVwZW5kIHRoZSBjb3JyZWN0IHF1ZXJ5IHN0cmluZyBwYXJhbWV0ZXIgdG8gdGhlIHVybC5cclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC51cmwgPSB1cmwgKyAodXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArIHRva2VuICsgZnJhZ21lbnQ7XHJcblxyXG4gICAgICAgICAgICAvLyBBdHRlbXB0IHRvIGF2b2lkIHN0b3JpbmcgdGhlIHVybCBpbiBwcm94aWVzLCBzaW5jZSB0aGUgYWNjZXNzIHRva2VuXHJcbiAgICAgICAgICAgIC8vIGlzIGV4cG9zZWQgaW4gdGhlIHF1ZXJ5IHBhcmFtZXRlcnMuXHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVycy5QcmFnbWEgPSAnbm8tc3RvcmUnO1xyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnNbJ0NhY2hlLUNvbnRyb2wnXSA9ICduby1zdG9yZSc7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gcmVxdWVzdE9iamVjdDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIHJlcXVlc3Qob3B0aW9ucykge1xyXG4gICAgICAgIGxldCByZXF1ZXN0T3B0aW9uc1Jlc3VsdCA9IHJlcXVlc3RPcHRpb25zKHRoaXMuc2lnbihvcHRpb25zKSwgdGhpcy5jbGllbnQub3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zUmVzdWx0KTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgXHJcbiAgICBwdWJsaWMgcmVmcmVzaChvcHRpb25zKTphbnkge1xyXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcclxuXHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLnJlZnJlc2hUb2tlbikge1xyXG4gICAgICAgICAgICByZXR1cm4gbmV3IEVycm9yKCdObyByZWZyZXNoIHRva2VuIHNldCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4gICAgICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbiAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICBib2R5OiB7XHJcbiAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxyXG4gICAgICAgICAgICBncmFudF90eXBlOiAncmVmcmVzaF90b2tlbidcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0sIG9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgYm9keSA9IGhhbmRsZUF1dGhSZXNwb25zZShyZXNwb25zZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgLy9UT0RPOiBUcmF0YXIgcXVhbmRvIGV4Y2VwdGlvblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXRvcm5vID0gKGZ1bmN0aW9uIChkYXRhKSB7XHJcbiAgICAgICAgICAgIHNlbGYuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICAgICAgc2VsZi5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcblxyXG4gICAgICAgICAgICBzZWxmLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHNlbGY7XHJcbiAgICAgICAgfSkoYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJldG9ybm87XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGdldCBleHBpcmVkKCkgOiBib29sZWFuXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKHRoaXMuZXhwaXJlcykge1xyXG4gICAgICAgICAgICByZXR1cm4gRGF0ZS5ub3coKSA+IHRoaXMuZXhwaXJlcy5nZXRUaW1lKClcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgICAgICBcclxuXHJcbiAgICAgICAgXHJcbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IHJlc291cmNlIG93bmVyIHBhc3N3b3JkIGNyZWRlbnRpYWxzIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4zXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIE93bmVyRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIE1ha2UgYSByZXF1ZXN0IG9uIGJlaGFsZiBvZiB0aGUgdXNlciBjcmVkZW50aWFscyB0byBnZXQgYW4gYWNjZXMgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHVzZXJuYW1lXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIHBhc3N3b3JkXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBPd25lckZsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcclxuLy8gICAgICAgcGFzc3dvcmQ6IHBhc3N3b3JkLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAncGFzc3dvcmQnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEZsb3dcclxue1xyXG4gICAgY2xpZW50OiBDbGllbnRPQXV0aDI7XHJcbiAgICBcclxuICAgIGNvbnN0cnVjdG9yKGNsaWVudCkge1xyXG4gICAgICAgIHRoaXMuY2xpZW50ID0gY2xpZW50O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZ2V0VXNlckluZm8oYWNjZXNzVG9rZW46IHN0cmluZykgOiBVc2VySW5mb1Jlc3BvbnNlXHJcbiAgICB7XHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgIHVybDogdGhpcy5jbGllbnQub3B0aW9ucy51c2VySW5mb1VyaSxcclxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxyXG4gICAgICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuICAgICAgICAgICAgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgYWNjZXNzVG9rZW5cclxuICAgICAgICB9KVxyXG4gICAgICAgIH0sIHRoaXMuY2xpZW50Lm9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBcclxuICAgICAgICBsZXQgcmVzcG9uc2VKU09OID0gSlNPTi5wYXJzZShyZXNwb25zZSk7XHJcbiAgICAgICAgbGV0IHVzZXJJbmZvUmVzcG9uc2UgPSBuZXcgVXNlckluZm9SZXNwb25zZShyZXNwb25zZUpTT04uc3ViKTtcclxuICAgICAgICB1c2VySW5mb1Jlc3BvbnNlID0gZXh0ZW5kKHVzZXJJbmZvUmVzcG9uc2UsIHJlc3BvbnNlSlNPTik7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHVzZXJJbmZvUmVzcG9uc2U7XHJcbiAgICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTdXBwb3J0IGltcGxpY2l0IE9BdXRoIDIuMCBncmFudC5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4yXHJcbiAqXHJcbiAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuICovXHJcbmV4cG9ydCBjbGFzcyBUb2tlbkZsb3cgZXh0ZW5kcyBGbG93XHJcbntcclxuICAgIHB1YmxpYyBnZXRVcmkob3B0aW9ucz86YW55KSB7XHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICd0b2tlbicpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRUb2tlbih1cmksIHN0YXRlPywgb3B0aW9ucz8pIFxyXG4gICAge1xyXG4gICAgICAgIC8vb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgLy8gdmFyIHVybCA9IHBhcnNlVXJsKHVyaSlcclxuICAgICAgICAvLyB2YXIgZXhwZWN0ZWRVcmwgPSBwYXJzZVVybChvcHRpb25zLnJlZGlyZWN0VXJpKVxyXG5cclxuICAgICAgICAvLyBpZiAodXJsLnBhdGhuYW1lICE9PSBleHBlY3RlZFVybC5wYXRobmFtZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyAvLyBJZiBubyBxdWVyeSBzdHJpbmcgb3IgZnJhZ21lbnQgZXhpc3RzLCB3ZSB3b24ndCBiZSBhYmxlIHRvIHBhcnNlXHJcbiAgICAgICAgLy8gLy8gYW55IHVzZWZ1bCBpbmZvcm1hdGlvbiBmcm9tIHRoZSB1cmkuXHJcbiAgICAgICAgLy8gaWYgKCF1cmwuaGFzaCAmJiAhdXJsLnNlYXJjaCkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignVW5hYmxlIHRvIHByb2Nlc3MgdXJpOiAnICsgdXJpKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIEV4dHJhY3QgZGF0YSBmcm9tIGJvdGggdGhlIGZyYWdtZW50IGFuZCBxdWVyeSBzdHJpbmcuIFRoZSBmcmFnbWVudCBpcyBtb3N0XHJcbiAgICAgICAgLy8gaW1wb3J0YW50LCBidXQgdGhlIHF1ZXJ5IHN0cmluZyBpcyBhbHNvIHVzZWQgYmVjYXVzZSBzb21lIE9BdXRoIDIuMFxyXG4gICAgICAgIC8vIGltcGxlbWVudGF0aW9ucyAoSW5zdGFncmFtKSBoYXZlIGEgYnVnIHdoZXJlIHN0YXRlIGlzIHBhc3NlZCB2aWEgcXVlcnkuXHJcbiAgICAgICAgLy8gdmFyIGRhdGEgPSBleHRlbmQoXHJcbiAgICAgICAgLy8gICAgIHVybC5xdWVyeSA/IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KSA6IHt9LFxyXG4gICAgICAgIC8vICAgICB1cmwuaGFzaCA/IHBhcnNlUXVlcnkodXJsLmhhc2guc3Vic3RyKDEpKSA6IHt9XHJcbiAgICAgICAgLy8gKVxyXG5cclxuICAgICAgICAvLyB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIGlmIHRoZSBxdWVyeSBzdHJpbmcgd2FzIHBvcHVsYXRlZCB3aXRoIGEga25vd24gZXJyb3IuXHJcbiAgICAgICAgLy8gaWYgKGVycikge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gQ2hlY2sgd2hldGhlciB0aGUgc3RhdGUgbWF0Y2hlcy5cclxuICAgICAgICAvLyBpZiAoc3RhdGUgIT0gbnVsbCAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4gICAgICAgIC8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignSW52YWxpZCBzdGF0ZTogJyArIGRhdGEuc3RhdGUpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgZnVuY3Rpb24gUGFyc2VhclVybCh1cmw6IHN0cmluZylcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKHVybC5pbmRleE9mKCcjJykgIT09IC0xKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdXJsLnN1YnN0cih1cmwuaW5kZXhPZignIycpLHVybC5sZW5ndGgpLnJlcGxhY2UoJz8nLCcnKS5yZXBsYWNlKCcjJywnJykuc3BsaXQoJyYnKS5yZWR1Y2UoZnVuY3Rpb24ocyxjKXt2YXIgdD1jLnNwbGl0KCc9Jyk7c1t0WzBdXT10WzFdO3JldHVybiBzO30se30pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJz8nKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IHVybFBhcnNlYWRhID0gUGFyc2VhclVybCh1cmkpO1xyXG5cclxuICAgICAgICBsZXQgZGF0YSA9IHVybFBhcnNlYWRhO1xyXG5cclxuICAgICAgICAvLyBJbml0YWxpemUgYSBuZXcgdG9rZW4gYW5kIHJldHVybi5cclxuICAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHRoaXMuY2xpZW50LCBkYXRhKTtcclxuICAgIH1cclxuICAgXHJcbn1cclxuICAgIFxyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQ2xhaW1hYmxlXHJcbntcclxuICAgIGdldENsYWltKGNsYWltTmFtZTogc3RyaW5nKVxyXG4gICAge1xyXG4gICAgICAgIHJldHVybiAoPGFueT50aGlzKVtjbGFpbU5hbWVdO1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgVXNlckluZm9SZXNwb25zZSBleHRlbmRzIENsYWltYWJsZVxyXG57XHJcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3ViOnN0cmluZykgXHJcbiAgICB7XHJcbiAgICAgICAgc3VwZXIoKTtcclxuICAgIH1cclxufVxyXG4gICAgXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGNsaWVudCBjcmVkZW50aWFscyBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuNFxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDcmVkZW50aWFsc0Zsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyB0aGUgY2xpZW50IGNyZWRlbnRpYWxzLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENyZWRlbnRpYWxzRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAob3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHJldHVybiB0aGlzLmNsaWVudC5fcmVxdWVzdChyZXF1ZXN0T3B0aW9ucyh7XHJcbi8vICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbi8vICAgICBtZXRob2Q6ICdQT1NUJyxcclxuLy8gICAgIGhlYWRlcnM6IGV4dGVuZChERUZBVUxUX0hFQURFUlMsIHtcclxuLy8gICAgICAgQXV0aG9yaXphdGlvbjogYXV0aChvcHRpb25zLmNsaWVudElkLCBvcHRpb25zLmNsaWVudFNlY3JldClcclxuLy8gICAgIH0pLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICdjbGllbnRfY3JlZGVudGlhbHMnXHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgYXV0aG9yaXphdGlvbiBjb2RlIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIENvZGVGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2VuZXJhdGUgdGhlIHVyaSBmb3IgZG9pbmcgdGhlIGZpcnN0IHJlZGlyZWN0LlxyXG4vLyAgKlxyXG4vLyAgKiBAcmV0dXJuIHtTdHJpbmd9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VXJpID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIHJldHVybiBjcmVhdGVVcmkob3B0aW9ucywgJ2NvZGUnKVxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogR2V0IHRoZSBjb2RlIHRva2VuIGZyb20gdGhlIHJlZGlyZWN0ZWQgdXJpIGFuZCBtYWtlIGFub3RoZXIgcmVxdWVzdCBmb3JcclxuLy8gICogdGhlIHVzZXIgYWNjZXNzIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICB1cmlcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgW3N0YXRlXVxyXG4vLyAgKiBAcGFyYW0gIHtPYmplY3R9ICBbb3B0aW9uc11cclxuLy8gICogQHJldHVybiB7UHJvbWlzZX1cclxuLy8gICovXHJcbi8vIENvZGVGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1cmksIHN0YXRlLCBvcHRpb25zKSB7XHJcbi8vICAgdmFyIHNlbGYgPSB0aGlzXHJcblxyXG4vLyAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucylcclxuXHJcbi8vICAgZXhwZWN0cyhvcHRpb25zLCBbXHJcbi8vICAgICAnY2xpZW50SWQnLFxyXG4vLyAgICAgJ2NsaWVudFNlY3JldCcsXHJcbi8vICAgICAncmVkaXJlY3RVcmknLFxyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbi8vICAgdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbi8vICAgaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdTaG91bGQgbWF0Y2ggcmVkaXJlY3QgdXJpOiAnICsgdXJpKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmICghdXJsLnNlYXJjaCkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICB2YXIgZGF0YSA9IHBhcnNlUXVlcnkodXJsLnF1ZXJ5KVxyXG4vLyAgIHZhciBlcnIgPSBnZXRBdXRoRXJyb3IoZGF0YSlcclxuXHJcbi8vICAgaWYgKGVycikge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuLy8gICB9XHJcblxyXG4vLyAgIGlmIChzdGF0ZSAmJiBkYXRhLnN0YXRlICE9PSBzdGF0ZSkge1xyXG4vLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6JyArIGRhdGEuc3RhdGUpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgLy8gQ2hlY2sgd2hldGhlciB0aGUgcmVzcG9uc2UgY29kZSBpcyBzZXQuXHJcbi8vICAgaWYgKCFkYXRhLmNvZGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdNaXNzaW5nIGNvZGUsIHVuYWJsZSB0byByZXF1ZXN0IHRva2VuJykpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTKSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgY29kZTogZGF0YS5jb2RlLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnYXV0aG9yaXphdGlvbl9jb2RlJyxcclxuLy8gICAgICAgcmVkaXJlY3RfdXJpOiBvcHRpb25zLnJlZGlyZWN0VXJpLFxyXG4vLyAgICAgICBjbGllbnRfaWQ6IG9wdGlvbnMuY2xpZW50SWQsXHJcbi8vICAgICAgIGNsaWVudF9zZWNyZXQ6IG9wdGlvbnMuY2xpZW50U2VjcmV0XHJcbi8vICAgICB9XHJcbi8vICAgfSwgb3B0aW9ucykpXHJcbi8vICAgICAudGhlbihoYW5kbGVBdXRoUmVzcG9uc2UpXHJcbi8vICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xyXG4vLyAgICAgICByZXR1cm4gbmV3IENsaWVudE9BdXRoMlRva2VuKHNlbGYuY2xpZW50LCBkYXRhKVxyXG4vLyAgICAgfSlcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIFN1cHBvcnQgSlNPTiBXZWIgVG9rZW4gKEpXVCkgQmVhcmVyIFRva2VuIE9BdXRoIDIuMCBncmFudC5cclxuLy8gICpcclxuLy8gICogUmVmZXJlbmNlOiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvZHJhZnQtaWV0Zi1vYXV0aC1qd3QtYmVhcmVyLTEyI3NlY3Rpb24tMi4xXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSB7Q2xpZW50T0F1dGgyfSBjbGllbnRcclxuLy8gICovXHJcbi8vIGZ1bmN0aW9uIEp3dEJlYXJlckZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiB1c2luZyBhIEpXVCB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7c3RyaW5nfSB0b2tlbiBBIEpXVCB0b2tlbi5cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBKd3RCZWFyZXJGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh0b2tlbiwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2FjY2Vzc1Rva2VuVXJpJ1xyXG4vLyAgIF0pXHJcblxyXG4vLyAgIHZhciBoZWFkZXJzID0gZXh0ZW5kKERFRkFVTFRfSEVBREVSUylcclxuXHJcbi8vICAgLy8gQXV0aGVudGljYXRpb24gb2YgdGhlIGNsaWVudCBpcyBvcHRpb25hbCwgYXMgZGVzY3JpYmVkIGluXHJcbi8vICAgLy8gU2VjdGlvbiAzLjIuMSBvZiBPQXV0aCAyLjAgW1JGQzY3NDldXHJcbi8vICAgaWYgKG9wdGlvbnMuY2xpZW50SWQpIHtcclxuLy8gICAgIGhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgfVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBoZWFkZXJzLFxyXG4vLyAgICAgYm9keToge1xyXG4vLyAgICAgICBzY29wZTogc2FuaXRpemVTY29wZShvcHRpb25zLnNjb3BlcyksXHJcbi8vICAgICAgIGdyYW50X3R5cGU6ICd1cm46aWV0ZjpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTpqd3QtYmVhcmVyJyxcclxuLy8gICAgICAgYXNzZXJ0aW9uOiB0b2tlblxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuIl19
