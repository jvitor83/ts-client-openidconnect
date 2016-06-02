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

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIkNsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7OztRQUtJLGNBQWMsRUFFZCxNQUFNLEVBa0NOLGVBQWUsRUFZZixlQUFlO0lBMkRuQixpQkFBa0IsR0FBRyxFQUFFLEtBQUs7UUFDMUIsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUM7WUFDdEMsSUFBSSxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBRW5CLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDO2dCQUN0QixNQUFNLElBQUksU0FBUyxDQUFDLFlBQVksR0FBRyxJQUFJLEdBQUcsWUFBWSxDQUFDLENBQUE7WUFDekQsQ0FBQztRQUNILENBQUM7SUFDSCxDQUFDO0lBUUQsc0JBQXVCLElBQUk7UUFDekIsSUFBSSxPQUFPLEdBQUcsZUFBZSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUM7WUFDdkMsSUFBSSxDQUFDLEtBQUs7WUFDVixJQUFJLENBQUMsYUFBYSxDQUFBO1FBR3BCLE1BQU0sQ0FBQyxPQUFPLElBQUksSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7SUFDdEMsQ0FBQztJQVFELDRCQUE2QixHQUFHO1FBQzlCLElBQUksSUFBSSxHQUFHLEdBQUcsQ0FBQyxJQUFJLENBQUM7UUFDcEIsSUFBSSxHQUFHLEdBQUcsWUFBWSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBRzdCLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDUixNQUFNLENBQUMsR0FBRyxDQUFDO1FBQ2IsQ0FBQztRQUVELE1BQU0sQ0FBQyxJQUFJLENBQUM7SUFDZCxDQUFDO0lBUUQsdUJBQXdCLE1BQU07UUFDNUIsTUFBTSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDbkUsQ0FBQztJQVNELG1CQUFvQixPQUFPLEVBQUUsU0FBUztRQUVwQyxPQUFPLENBQUMsT0FBTyxFQUFFO1lBQ2YsVUFBVTtZQUNWLGFBQWE7WUFDYixrQkFBa0I7U0FDbkIsQ0FBQyxDQUFDO1FBRUgsSUFBSSxRQUFRLEdBQUcsa0JBQWtCLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3BELElBQUksV0FBVyxHQUFHLGtCQUFrQixDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUMxRCxJQUFJLE1BQU0sR0FBRyxrQkFBa0IsQ0FBQyxhQUFhLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7UUFDL0QsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLGdCQUFnQixHQUFHLGFBQWEsR0FBRyxRQUFRO1lBQzNELGdCQUFnQixHQUFHLFdBQVc7WUFDOUIsU0FBUyxHQUFHLE1BQU07WUFDbEIsaUJBQWlCLEdBQUcsU0FBUyxDQUFDO1FBRWhDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQ2xCLEdBQUcsSUFBSSxTQUFTLEdBQUcsa0JBQWtCLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3ZELENBQUM7UUFFRCxNQUFNLENBQUMsR0FBRyxDQUFDO0lBQ2IsQ0FBQztJQVNELGNBQWUsUUFBUSxFQUFFLFFBQVE7UUFDL0IsTUFBTSxDQUFDLFFBQVEsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxHQUFHLEdBQUcsR0FBRyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUNwRSxDQUFDO0lBUUQsZ0JBQWlCLEdBQUc7UUFDbEIsTUFBTSxDQUFDLEdBQUcsSUFBSSxJQUFJLEdBQUcsRUFBRSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN4QyxDQUFDO0lBY0Qsd0JBQXlCLGNBQWMsRUFBRSxPQUFPO1FBRTlDLE1BQU0sQ0FBQyxNQUFNLENBQUMsY0FBYyxFQUFFO1lBQzVCLElBQUksRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxjQUFjLENBQUMsSUFBSSxDQUFDO1lBQy9DLEtBQUssRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxjQUFjLENBQUMsS0FBSyxDQUFDO1lBQ2xELE9BQU8sRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxjQUFjLENBQUMsT0FBTyxDQUFDO1lBQ3hELE9BQU8sRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxjQUFjLENBQUMsT0FBTyxDQUFDO1NBQ3pELENBQUMsQ0FBQztJQUNMLENBQUM7Ozs7WUF2T0csY0FBYyxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsY0FBYyxDQUFDO1lBRWpELE1BQU0sR0FBRztnQkFBZ0IsY0FBa0I7cUJBQWxCLFdBQWtCLENBQWxCLHNCQUFrQixDQUFsQixJQUFrQjtvQkFBbEIsNkJBQWtCOztnQkFDM0MsSUFBSSxNQUFNLEdBQUcsRUFBRSxDQUFBO2dCQUVmLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDO29CQUNuQyxJQUFJLE1BQU0sR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7b0JBRXBCLEdBQUcsQ0FBQyxDQUFDLElBQUksR0FBRyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUM7d0JBQ3JCLEVBQUUsQ0FBQyxDQUFDLGNBQWMsQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQzs0QkFDbkMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTt3QkFDN0IsQ0FBQztvQkFDTCxDQUFDO2dCQUNMLENBQUM7Z0JBRUQsTUFBTSxDQUFDLE1BQU0sQ0FBQztZQUNsQixDQUFDLENBQUE7WUFvQkcsZUFBZSxHQUFHO2dCQUNwQixRQUFRLEVBQUUscURBQXFEO2dCQUMvRCxjQUFjLEVBQUUsbUNBQW1DO2FBQ3BELENBQUE7WUFTRyxlQUFlLEdBQUc7Z0JBQ3BCLGlCQUFpQixFQUFFO29CQUNqQiwwREFBMEQ7b0JBQzFELHlEQUF5RDtvQkFDekQsa0NBQWtDO2lCQUNuQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsZ0JBQWdCLEVBQUU7b0JBQ2hCLHdEQUF3RDtvQkFDeEQsZ0RBQWdEO29CQUNoRCx5QkFBeUI7aUJBQzFCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxlQUFlLEVBQUU7b0JBQ2YsdURBQXVEO29CQUN2RCx1REFBdUQ7b0JBQ3ZELDJEQUEyRDtvQkFDM0QseURBQXlEO29CQUN6RCxpQkFBaUI7aUJBQ2xCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxxQkFBcUIsRUFBRTtvQkFDckIsMERBQTBEO29CQUMxRCx5QkFBeUI7aUJBQzFCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCx3QkFBd0IsRUFBRTtvQkFDeEIsc0RBQXNEO29CQUN0RCx1QkFBdUI7aUJBQ3hCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDWCxlQUFlLEVBQUU7b0JBQ2YsZ0VBQWdFO2lCQUNqRSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsMkJBQTJCLEVBQUU7b0JBQzNCLHFEQUFxRDtvQkFDckQsMENBQTBDO2lCQUMzQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ1gsZUFBZSxFQUFFO29CQUNmLHdEQUF3RDtpQkFDekQsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO2dCQUNYLGNBQWMsRUFBRTtvQkFDZCxvREFBb0Q7b0JBQ3BELDBEQUEwRDtvQkFDMUQsMERBQTBEO29CQUMxRCx5REFBeUQ7b0JBQ3pELHdCQUF3QjtpQkFDekIsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO2dCQUNYLHlCQUF5QixFQUFFO29CQUN6Qix3REFBd0Q7b0JBQ3hELDJEQUEyRDtvQkFDM0QsZ0JBQWdCO2lCQUNqQixDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7YUFDWixDQUFBO1lBMEhBLENBQUM7WUFvQkY7Z0JBUUksc0JBQVksT0FBWTtvQkFFcEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUM7b0JBR3ZCLElBQUksQ0FBQyxLQUFLLEdBQUcsSUFBSSxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUM7Z0JBSXJDLENBQUM7Z0JBRU0sa0NBQVcsR0FBbEIsVUFBbUIsTUFBYyxFQUFFLE9BQWUsRUFBRSxJQUFZLEVBQUUsSUFBUztvQkFFdkUsSUFBSSxPQUFPLEdBQUcsTUFBTSxDQUNoQixJQUFJLEVBQ0osT0FBTyxNQUFNLEtBQUssUUFBUSxHQUFHLEVBQUUsWUFBWSxFQUFFLE1BQU0sRUFBRSxHQUFHLE1BQU0sRUFDOUQsT0FBTyxPQUFPLEtBQUssUUFBUSxHQUFHLEVBQUUsYUFBYSxFQUFFLE9BQU8sRUFBRSxHQUFHLE9BQU8sRUFDbEUsT0FBTyxJQUFJLEtBQUssUUFBUSxHQUFHLEVBQUUsVUFBVSxFQUFFLElBQUksRUFBRSxHQUFHLElBQUksQ0FDekQsQ0FBQztvQkFFRixNQUFNLENBQUMsSUFBSSxpQkFBaUIsQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLENBQUM7Z0JBQ2hELENBQUM7Z0JBRU0sK0JBQVEsR0FBZixVQUFnQixhQUE4QjtvQkFFMUMsSUFBSSxPQUFPLEdBQUcsSUFBSSxjQUFjLEVBQUUsQ0FBQztvQkFFbkMsT0FBTyxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsTUFBTSxFQUFFLGFBQWEsQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDLENBQUM7b0JBRTdELElBQUksT0FBTyxHQUFHLGFBQWEsQ0FBQyxPQUFPLENBQUM7b0JBQ3BDLEdBQUcsQ0FBQSxDQUFDLElBQUksTUFBTSxJQUFJLE9BQU8sQ0FBQyxDQUMxQixDQUFDO3dCQUNHLE9BQU8sQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7b0JBQ3RELENBQUM7b0JBRUQsT0FBTyxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLENBQUM7b0JBRWpDLE1BQU0sQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDO2dCQWE1QixDQUFDO2dCQUNMLG1CQUFDO1lBQUQsQ0EzREEsQUEyREMsSUFBQTtZQTNERCx1Q0EyREMsQ0FBQTtZQThCRDtnQkE2QkksMkJBQVksTUFBTSxFQUFFLElBQUk7b0JBQ3BCLElBQUksQ0FBQyxNQUFNLEdBQUcsTUFBTSxDQUFDO29CQUNyQixJQUFJLENBQUMsSUFBSSxHQUFHLElBQUksQ0FBQztvQkFDakIsSUFBSSxDQUFDLFNBQVMsR0FBRyxJQUFJLENBQUMsVUFBVSxJQUFJLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxFQUFFLENBQUM7b0JBQ2xFLElBQUksQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLFlBQVksQ0FBQztvQkFDckMsSUFBSSxDQUFDLFlBQVksR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFDO29CQUN2QyxJQUFJLENBQUMsYUFBYSxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUM7b0JBRW5DLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFDO2dCQUNwQyxDQUFDO2dCQTFCRCxzQkFBSSwwQ0FBVzt5QkFBZjt3QkFFSSxFQUFFLENBQUEsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQ2hCLENBQUM7NEJBQ0csSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDO3dCQUNuQixDQUFDO3dCQUVELE1BQU0sQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDO29CQUM3QixDQUFDO3lCQUVELFVBQWdCLEtBQVk7d0JBRXhCLElBQUksQ0FBQyxZQUFZLEdBQUcsS0FBSyxDQUFDO29CQUM5QixDQUFDOzs7bUJBTEE7Z0JBcUJNLHFDQUFTLEdBQWhCLFVBQWlCLFFBQVE7b0JBRXJCLEVBQUUsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQ3JCLENBQUM7d0JBQ0csSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLElBQUksRUFBRSxDQUFDO3dCQUMxQixJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxHQUFHLFFBQVEsQ0FBQyxDQUFDO29CQUNsRSxDQUFDO29CQUNELElBQUksQ0FDSixDQUFDO3dCQUNHLElBQUksQ0FBQyxPQUFPLEdBQUcsU0FBUyxDQUFDO29CQUM3QixDQUFDO29CQUNELE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDO2dCQUN4QixDQUFDO2dCQUVNLGdDQUFJLEdBQVgsVUFBWSxhQUFhO29CQUNyQixFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDO3dCQUNwQixNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUE7b0JBQzFELENBQUM7b0JBRUQsYUFBYSxDQUFDLE9BQU8sR0FBRyxhQUFhLENBQUMsT0FBTyxJQUFJLEVBQUUsQ0FBQTtvQkFFbkQsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFNBQVMsS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDO3dCQUM5QixhQUFhLENBQUMsT0FBTyxDQUFDLGFBQWEsR0FBRyxTQUFTLEdBQUcsSUFBSSxDQUFDLFdBQVcsQ0FBQztvQkFDdkUsQ0FBQztvQkFBQyxJQUFJLENBQUMsQ0FBQzt3QkFDSixJQUFJLEtBQUssR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQzt3QkFDekMsSUFBSSxLQUFLLEdBQUcsZUFBZSxHQUFHLElBQUksQ0FBQyxXQUFXLENBQUM7d0JBQy9DLElBQUksR0FBRyxHQUFHLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsd0JBQXdCLEVBQUUsRUFBRSxDQUFDLENBQUM7d0JBQ3pELElBQUksUUFBUSxHQUFHLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxHQUFHLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQzt3QkFHOUMsYUFBYSxDQUFDLEdBQUcsR0FBRyxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLEdBQUcsR0FBRyxHQUFHLENBQUMsR0FBRyxLQUFLLEdBQUcsUUFBUSxDQUFDO3dCQUlqRixhQUFhLENBQUMsT0FBTyxDQUFDLE1BQU0sR0FBRyxVQUFVLENBQUM7d0JBQzFDLGFBQWEsQ0FBQyxPQUFPLENBQUMsZUFBZSxDQUFDLEdBQUcsVUFBVSxDQUFDO29CQUN4RCxDQUFDO29CQUVELE1BQU0sQ0FBQyxhQUFhLENBQUM7Z0JBQ3pCLENBQUM7Z0JBRU0sbUNBQU8sR0FBZCxVQUFlLE9BQU87b0JBQ2xCLElBQUksb0JBQW9CLEdBQUcsY0FBYyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQztvQkFDbkYsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLG9CQUFvQixDQUFDLENBQUM7Z0JBQ3RELENBQUM7Z0JBR00sbUNBQU8sR0FBZCxVQUFlLE9BQVE7b0JBQ25CLElBQUksSUFBSSxHQUFHLElBQUksQ0FBQztvQkFFaEIsT0FBTyxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQztvQkFFL0MsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQzt3QkFDckIsTUFBTSxDQUFDLElBQUksS0FBSyxDQUFDLHNCQUFzQixDQUFDLENBQUM7b0JBQzdDLENBQUM7b0JBR0QsSUFBSSxRQUFRLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsY0FBYyxDQUFDO3dCQUMvQyxHQUFHLEVBQUUsT0FBTyxDQUFDLGNBQWM7d0JBQzNCLE1BQU0sRUFBRSxNQUFNO3dCQUNkLE9BQU8sRUFBRSxNQUFNLENBQUMsZUFBZSxFQUFFOzRCQUNqQyxhQUFhLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsT0FBTyxDQUFDLFlBQVksQ0FBQzt5QkFDMUQsQ0FBQzt3QkFDRixJQUFJLEVBQUU7NEJBQ04sYUFBYSxFQUFFLElBQUksQ0FBQyxZQUFZOzRCQUNoQyxVQUFVLEVBQUUsZUFBZTt5QkFDMUI7cUJBQ0osRUFBRSxPQUFPLENBQUMsQ0FBQyxDQUFDO29CQUdiLElBQUksSUFBSSxHQUFHLGtCQUFrQixDQUFDLFFBQVEsQ0FBQyxDQUFDO29CQUl4QyxJQUFJLE9BQU8sR0FBRyxDQUFDLFVBQVUsSUFBSTt3QkFDekIsSUFBSSxDQUFDLFdBQVcsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDO3dCQUNyQyxJQUFJLENBQUMsWUFBWSxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUM7d0JBRXZDLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFDO3dCQUVoQyxNQUFNLENBQUMsSUFBSSxDQUFDO29CQUNoQixDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQztvQkFFVCxNQUFNLENBQUMsT0FBTyxDQUFDO2dCQUNuQixDQUFDO2dCQUVELHNCQUFJLHNDQUFPO3lCQUFYO3dCQUVJLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDOzRCQUNmLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsQ0FBQzt3QkFDL0MsQ0FBQzt3QkFFRCxNQUFNLENBQUMsS0FBSyxDQUFDO29CQUNqQixDQUFDOzs7bUJBQUE7Z0JBS0wsd0JBQUM7WUFBRCxDQTNJQSxBQTJJQyxJQUFBO1lBM0lELGlEQTJJQyxDQUFBO1lBa0REO2dCQUlJLGNBQVksTUFBTTtvQkFDZCxJQUFJLENBQUMsTUFBTSxHQUFHLE1BQU0sQ0FBQztnQkFDekIsQ0FBQztnQkFFTSwwQkFBVyxHQUFsQixVQUFtQixXQUFtQjtvQkFFbEMsSUFBSSxRQUFRLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsY0FBYyxDQUFDO3dCQUNuRCxHQUFHLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsV0FBVzt3QkFDcEMsTUFBTSxFQUFFLEtBQUs7d0JBQ2IsT0FBTyxFQUFFLE1BQU0sQ0FBQyxlQUFlLEVBQUU7NEJBQzdCLGFBQWEsRUFBRSxTQUFTLEdBQUcsV0FBVzt5QkFDekMsQ0FBQztxQkFDRCxFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztvQkFHekIsSUFBSSxZQUFZLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsQ0FBQztvQkFDeEMsSUFBSSxnQkFBZ0IsR0FBRyxJQUFJLGdCQUFnQixDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQztvQkFDOUQsZ0JBQWdCLEdBQUcsTUFBTSxDQUFDLGdCQUFnQixFQUFFLFlBQVksQ0FBQyxDQUFDO29CQUUxRCxNQUFNLENBQUMsZ0JBQWdCLENBQUM7Z0JBQzVCLENBQUM7Z0JBQ0wsV0FBQztZQUFELENBekJBLEFBeUJDLElBQUE7WUF6QkQsdUJBeUJDLENBQUE7WUFTRDtnQkFBK0IsNkJBQUk7Z0JBQW5DO29CQUErQiw4QkFBSTtnQkFnRW5DLENBQUM7Z0JBOURVLDBCQUFNLEdBQWIsVUFBYyxPQUFZO29CQUN0QixPQUFPLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFDO29CQUMvQyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQztnQkFDdkMsQ0FBQztnQkFFTSw0QkFBUSxHQUFmLFVBQWdCLEdBQUcsRUFBRSxLQUFNLEVBQUUsT0FBUTtvQkFxQ2pDLG9CQUFvQixHQUFXO3dCQUUzQixFQUFFLENBQUEsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQzNCLENBQUM7NEJBQ0csTUFBTSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsRUFBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBQyxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFDLEVBQUUsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNLENBQUMsVUFBUyxDQUFDLEVBQUMsQ0FBQyxJQUFFLElBQUksQ0FBQyxHQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUEsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFBLENBQUMsRUFBQyxFQUFFLENBQUMsQ0FBQzt3QkFDbEssQ0FBQzt3QkFDRCxJQUFJLENBQ0osQ0FBQzs0QkFDRyxNQUFNLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUMsRUFBRSxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxVQUFTLENBQUMsRUFBQyxDQUFDLElBQUUsSUFBSSxDQUFDLEdBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUEsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxDQUFDO3dCQUNsSyxDQUFDO29CQUNMLENBQUM7b0JBRUQsSUFBSSxXQUFXLEdBQUcsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDO29CQUVsQyxJQUFJLElBQUksR0FBRyxXQUFXLENBQUM7b0JBR3ZCLE1BQU0sQ0FBQyxJQUFJLGlCQUFpQixDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsSUFBSSxDQUFDLENBQUM7Z0JBQ3BELENBQUM7Z0JBRUwsZ0JBQUM7WUFBRCxDQWhFQSxBQWdFQyxDQWhFOEIsSUFBSSxHQWdFbEM7WUFoRUQsaUNBZ0VDLENBQUE7WUFFRDtnQkFBQTtnQkFNQSxDQUFDO2dCQUpHLDRCQUFRLEdBQVIsVUFBUyxTQUFpQjtvQkFFdEIsTUFBTSxDQUFPLElBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQztnQkFDbEMsQ0FBQztnQkFDTCxnQkFBQztZQUFELENBTkEsQUFNQyxJQUFBO1lBTkQsaUNBTUMsQ0FBQTtZQUVEO2dCQUFzQyxvQ0FBUztnQkFFM0MsMEJBQW1CLEdBQVU7b0JBRXpCLGlCQUFPLENBQUM7b0JBRk8sUUFBRyxHQUFILEdBQUcsQ0FBTztnQkFHN0IsQ0FBQztnQkFDTCx1QkFBQztZQUFELENBTkEsQUFNQyxDQU5xQyxTQUFTLEdBTTlDO1lBTkQsK0NBTUMsQ0FBQSIsImZpbGUiOiJDbGllbnQuanMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBpbXBvcnQgJ3h0ZW5kJztcclxuLy8gaW1wb3J0ICdwb3BzaWNsZSc7XHJcbi8vIGltcG9ydCAncXVlcnlzdHJpbmcnO1xyXG4vLyBpbXBvcnQgJ3VybCc7XHJcblxyXG52YXIgaGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xyXG5cclxudmFyIGV4dGVuZCA9IGZ1bmN0aW9uIGV4dGVuZCguLi5hcmdzOkFycmF5PGFueT4pOmFueSB7XHJcbiAgICB2YXIgdGFyZ2V0ID0ge31cclxuXHJcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICB2YXIgc291cmNlID0gYXJnc1tpXVxyXG5cclxuICAgICAgICBmb3IgKHZhciBrZXkgaW4gc291cmNlKSB7XHJcbiAgICAgICAgICAgIGlmIChoYXNPd25Qcm9wZXJ0eS5jYWxsKHNvdXJjZSwga2V5KSkge1xyXG4gICAgICAgICAgICAgICAgdGFyZ2V0W2tleV0gPSBzb3VyY2Vba2V5XVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0YXJnZXQ7XHJcbn1cclxuXHJcblxyXG5cclxuLy92YXIgcG9wc2ljbGUgIDphbnk7XHJcbi8vdmFyIHBhcnNlUXVlcnkgOmFueTtcclxuLy92YXIgcGFyc2VVcmwgIDphbnk7XHJcblxyXG4vLyB2YXIgZXh0ZW5kID0gcmVxdWlyZSgneHRlbmQnKVxyXG4vLyB2YXIgcG9wc2ljbGUgPSByZXF1aXJlKCdwb3BzaWNsZScpXHJcbi8vIHZhciBwYXJzZVF1ZXJ5ID0gcmVxdWlyZSgncXVlcnlzdHJpbmcnKS5wYXJzZVxyXG4vLyB2YXIgcGFyc2VVcmwgPSByZXF1aXJlKCd1cmwnKS5wYXJzZVxyXG5cclxuLy92YXIgYnRvYSA9IHR5cGVvZiBCdWZmZXIgPT09ICdmdW5jdGlvbicgPyBidG9hQnVmZmVyIDogd2luZG93LmJ0b2FcclxuXHJcbi8qKlxyXG4gKiBEZWZhdWx0IGhlYWRlcnMgZm9yIGV4ZWN1dGluZyBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEB0eXBlIHtPYmplY3R9XHJcbiAqL1xyXG52YXIgREVGQVVMVF9IRUFERVJTID0ge1xyXG4gICdBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbiwgYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcclxuICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxufVxyXG5cclxuLyoqXHJcbiAqIEZvcm1hdCBlcnJvciByZXNwb25zZSB0eXBlcyB0byByZWd1bGFyIHN0cmluZ3MgZm9yIGRpc3BsYXlpbmcgdG8gY2xpZW50cy5cclxuICpcclxuICogUmVmZXJlbmNlOiBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM2NzQ5I3NlY3Rpb24tNC4xLjIuMVxyXG4gKlxyXG4gKiBAdHlwZSB7T2JqZWN0fVxyXG4gKi9cclxudmFyIEVSUk9SX1JFU1BPTlNFUyA9IHtcclxuICAnaW52YWxpZF9yZXF1ZXN0JzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0IGlzIG1pc3NpbmcgYSByZXF1aXJlZCBwYXJhbWV0ZXIsIGluY2x1ZGVzIGFuJyxcclxuICAgICdpbnZhbGlkIHBhcmFtZXRlciB2YWx1ZSwgaW5jbHVkZXMgYSBwYXJhbWV0ZXIgbW9yZSB0aGFuJyxcclxuICAgICdvbmNlLCBvciBpcyBvdGhlcndpc2UgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9jbGllbnQnOiBbXHJcbiAgICAnQ2xpZW50IGF1dGhlbnRpY2F0aW9uIGZhaWxlZCAoZS5nLiwgdW5rbm93biBjbGllbnQsIG5vJyxcclxuICAgICdjbGllbnQgYXV0aGVudGljYXRpb24gaW5jbHVkZWQsIG9yIHVuc3VwcG9ydGVkJyxcclxuICAgICdhdXRoZW50aWNhdGlvbiBtZXRob2QpLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnaW52YWxpZF9ncmFudCc6IFtcclxuICAgICdUaGUgcHJvdmlkZWQgYXV0aG9yaXphdGlvbiBncmFudCAoZS5nLiwgYXV0aG9yaXphdGlvbicsXHJcbiAgICAnY29kZSwgcmVzb3VyY2Ugb3duZXIgY3JlZGVudGlhbHMpIG9yIHJlZnJlc2ggdG9rZW4gaXMnLFxyXG4gICAgJ2ludmFsaWQsIGV4cGlyZWQsIHJldm9rZWQsIGRvZXMgbm90IG1hdGNoIHRoZSByZWRpcmVjdGlvbicsXHJcbiAgICAnVVJJIHVzZWQgaW4gdGhlIGF1dGhvcml6YXRpb24gcmVxdWVzdCwgb3Igd2FzIGlzc3VlZCB0bycsXHJcbiAgICAnYW5vdGhlciBjbGllbnQuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICd1bmF1dGhvcml6ZWRfY2xpZW50JzogW1xyXG4gICAgJ1RoZSBjbGllbnQgaXMgbm90IGF1dGhvcml6ZWQgdG8gcmVxdWVzdCBhbiBhdXRob3JpemF0aW9uJyxcclxuICAgICdjb2RlIHVzaW5nIHRoaXMgbWV0aG9kLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAndW5zdXBwb3J0ZWRfZ3JhbnRfdHlwZSc6IFtcclxuICAgICdUaGUgYXV0aG9yaXphdGlvbiBncmFudCB0eXBlIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlJyxcclxuICAgICdhdXRob3JpemF0aW9uIHNlcnZlci4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ2FjY2Vzc19kZW5pZWQnOiBbXHJcbiAgICAnVGhlIHJlc291cmNlIG93bmVyIG9yIGF1dGhvcml6YXRpb24gc2VydmVyIGRlbmllZCB0aGUgcmVxdWVzdC4nXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3Vuc3VwcG9ydGVkX3Jlc3BvbnNlX3R5cGUnOiBbXHJcbiAgICAnVGhlIGF1dGhvcml6YXRpb24gc2VydmVyIGRvZXMgbm90IHN1cHBvcnQgb2J0YWluaW5nJyxcclxuICAgICdhbiBhdXRob3JpemF0aW9uIGNvZGUgdXNpbmcgdGhpcyBtZXRob2QuJ1xyXG4gIF0uam9pbignICcpLFxyXG4gICdpbnZhbGlkX3Njb3BlJzogW1xyXG4gICAgJ1RoZSByZXF1ZXN0ZWQgc2NvcGUgaXMgaW52YWxpZCwgdW5rbm93biwgb3IgbWFsZm9ybWVkLidcclxuICBdLmpvaW4oJyAnKSxcclxuICAnc2VydmVyX2Vycm9yJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBlbmNvdW50ZXJlZCBhbiB1bmV4cGVjdGVkJyxcclxuICAgICdjb25kaXRpb24gdGhhdCBwcmV2ZW50ZWQgaXQgZnJvbSBmdWxmaWxsaW5nIHRoZSByZXF1ZXN0LicsXHJcbiAgICAnKFRoaXMgZXJyb3IgY29kZSBpcyBuZWVkZWQgYmVjYXVzZSBhIDUwMCBJbnRlcm5hbCBTZXJ2ZXInLFxyXG4gICAgJ0Vycm9yIEhUVFAgc3RhdHVzIGNvZGUgY2Fubm90IGJlIHJldHVybmVkIHRvIHRoZSBjbGllbnQnLFxyXG4gICAgJ3ZpYSBhbiBIVFRQIHJlZGlyZWN0LiknXHJcbiAgXS5qb2luKCcgJyksXHJcbiAgJ3RlbXBvcmFyaWx5X3VuYXZhaWxhYmxlJzogW1xyXG4gICAgJ1RoZSBhdXRob3JpemF0aW9uIHNlcnZlciBpcyBjdXJyZW50bHkgdW5hYmxlIHRvIGhhbmRsZScsXHJcbiAgICAndGhlIHJlcXVlc3QgZHVlIHRvIGEgdGVtcG9yYXJ5IG92ZXJsb2FkaW5nIG9yIG1haW50ZW5hbmNlJyxcclxuICAgICdvZiB0aGUgc2VydmVyLidcclxuICBdLmpvaW4oJyAnKVxyXG59XHJcblxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGlmIHByb3BlcnRpZXMgZXhpc3Qgb24gYW4gb2JqZWN0IGFuZCB0aHJvdyB3aGVuIHRoZXkgYXJlbid0LlxyXG4gKlxyXG4gKiBAdGhyb3dzIHtUeXBlRXJyb3J9IElmIGFuIGV4cGVjdGVkIHByb3BlcnR5IGlzIG1pc3NpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcclxuICogQHBhcmFtIHtBcnJheX0gIHByb3BzXHJcbiAqL1xyXG5mdW5jdGlvbiBleHBlY3RzIChvYmosIHByb3BzKSB7XHJcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwcm9wcy5sZW5ndGg7IGkrKykge1xyXG4gICAgdmFyIHByb3AgPSBwcm9wc1tpXVxyXG5cclxuICAgIGlmIChvYmpbcHJvcF0gPT0gbnVsbCkge1xyXG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcIicgKyBwcm9wICsgJ1wiIHRvIGV4aXN0JylcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBQdWxsIGFuIGF1dGhlbnRpY2F0aW9uIGVycm9yIGZyb20gdGhlIHJlc3BvbnNlIGRhdGEuXHJcbiAqXHJcbiAqIEBwYXJhbSAge09iamVjdH0gZGF0YVxyXG4gKiBAcmV0dXJuIHtTdHJpbmd9XHJcbiAqL1xyXG5mdW5jdGlvbiBnZXRBdXRoRXJyb3IgKGRhdGEpIHtcclxuICB2YXIgbWVzc2FnZSA9IEVSUk9SX1JFU1BPTlNFU1tkYXRhLmVycm9yXSB8fFxyXG4gICAgZGF0YS5lcnJvciB8fFxyXG4gICAgZGF0YS5lcnJvcl9tZXNzYWdlXHJcblxyXG4gIC8vIFJldHVybiBhbiBlcnJvciBpbnN0YW5jZSB3aXRoIHRoZSBtZXNzYWdlIGlmIGl0IGV4aXN0cy5cclxuICByZXR1cm4gbWVzc2FnZSAmJiBuZXcgRXJyb3IobWVzc2FnZSlcclxufVxyXG5cclxuLyoqXHJcbiAqIEhhbmRsZSB0aGUgYXV0aGVudGljYXRpb24gcmVzcG9uc2Ugb2JqZWN0LlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9ICByZXNcclxuICogQHJldHVybiB7UHJvbWlzZX1cclxuICovXHJcbmZ1bmN0aW9uIGhhbmRsZUF1dGhSZXNwb25zZSAocmVzKSB7XHJcbiAgdmFyIGRhdGEgPSByZXMuYm9keTtcclxuICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpO1xyXG5cclxuICAvLyBJZiB0aGUgcmVzcG9uc2UgY29udGFpbnMgYW4gZXJyb3IsIHJlamVjdCB0aGUgcmVmcmVzaCB0b2tlbi5cclxuICBpZiAoZXJyKSB7XHJcbiAgICByZXR1cm4gZXJyO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIGRhdGE7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBTYW5pdGl6ZSB0aGUgc2NvcGVzIG9wdGlvbiB0byBiZSBhIHN0cmluZy5cclxuICpcclxuICogQHBhcmFtICB7QXJyYXl9ICBzY29wZXNcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gc2FuaXRpemVTY29wZSAoc2NvcGVzKSB7XHJcbiAgcmV0dXJuIEFycmF5LmlzQXJyYXkoc2NvcGVzKSA/IHNjb3Blcy5qb2luKCcgJykgOiBzdHJpbmcoc2NvcGVzKTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBhIHJlcXVlc3QgdXJpIGJhc2VkIG9uIGFuIG9wdGlvbnMgb2JqZWN0IGFuZCB0b2tlbiB0eXBlLlxyXG4gKlxyXG4gKiBAcGFyYW0gIHtPYmplY3R9IG9wdGlvbnNcclxuICogQHBhcmFtICB7U3RyaW5nfSB0b2tlblR5cGVcclxuICogQHJldHVybiB7U3RyaW5nfVxyXG4gKi9cclxuZnVuY3Rpb24gY3JlYXRlVXJpIChvcHRpb25zLCB0b2tlblR5cGUpIHtcclxuICAvLyBDaGVjayB0aGUgcmVxdWlyZWQgcGFyYW1ldGVycyBhcmUgc2V0LlxyXG4gIGV4cGVjdHMob3B0aW9ucywgW1xyXG4gICAgJ2NsaWVudElkJyxcclxuICAgICdyZWRpcmVjdFVyaScsXHJcbiAgICAnYXV0aG9yaXphdGlvblVyaSdcclxuICBdKTtcclxuXHJcbiAgdmFyIGNsaWVudElkID0gZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuY2xpZW50SWQpO1xyXG4gIHZhciByZWRpcmVjdFVyaSA9IGVuY29kZVVSSUNvbXBvbmVudChvcHRpb25zLnJlZGlyZWN0VXJpKTtcclxuICB2YXIgc2NvcGVzID0gZW5jb2RlVVJJQ29tcG9uZW50KHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpKTtcclxuICB2YXIgdXJpID0gb3B0aW9ucy5hdXRob3JpemF0aW9uVXJpICsgJz9jbGllbnRfaWQ9JyArIGNsaWVudElkICtcclxuICAgICcmcmVkaXJlY3RfdXJpPScgKyByZWRpcmVjdFVyaSArXHJcbiAgICAnJnNjb3BlPScgKyBzY29wZXMgK1xyXG4gICAgJyZyZXNwb25zZV90eXBlPScgKyB0b2tlblR5cGU7XHJcblxyXG4gIGlmIChvcHRpb25zLnN0YXRlKSB7XHJcbiAgICB1cmkgKz0gJyZzdGF0ZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG9wdGlvbnMuc3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHVyaTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENyZWF0ZSBiYXNpYyBhdXRoIGhlYWRlci5cclxuICpcclxuICogQHBhcmFtICB7U3RyaW5nfSB1c2VybmFtZVxyXG4gKiBAcGFyYW0gIHtTdHJpbmd9IHBhc3N3b3JkXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIGF1dGggKHVzZXJuYW1lLCBwYXNzd29yZCkge1xyXG4gIHJldHVybiAnQmFzaWMgJyArIGJ0b2Eoc3RyaW5nKHVzZXJuYW1lKSArICc6JyArIHN0cmluZyhwYXNzd29yZCkpO1xyXG59XHJcblxyXG4vKipcclxuICogRW5zdXJlIGEgdmFsdWUgaXMgYSBzdHJpbmcuXHJcbiAqXHJcbiAqIEBwYXJhbSAge1N0cmluZ30gc3RyXHJcbiAqIEByZXR1cm4ge1N0cmluZ31cclxuICovXHJcbmZ1bmN0aW9uIHN0cmluZyAoc3RyKSB7XHJcbiAgcmV0dXJuIHN0ciA9PSBudWxsID8gJycgOiBTdHJpbmcoc3RyKTtcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBSZXF1ZXN0T3B0aW9ucyB7XHJcbiAgICBib2R5OiBhbnk7XHJcbiAgICBxdWVyeTogYW55O1xyXG4gICAgaGVhZGVyczogYW55O1xyXG4gICAgb3B0aW9uczogYW55O1xyXG4gICAgbWV0aG9kOiBzdHJpbmc7XHJcbiAgICB1cmw6IHN0cmluZztcclxufTtcclxuXHJcbi8qKlxyXG4gKiBNZXJnZSByZXF1ZXN0IG9wdGlvbnMgZnJvbSBhbiBvcHRpb25zIG9iamVjdC5cclxuICovXHJcbmZ1bmN0aW9uIHJlcXVlc3RPcHRpb25zIChyZXF1ZXN0T3B0aW9ucywgb3B0aW9ucyk6IFJlcXVlc3RPcHRpb25zIHtcclxuXHJcbiAgcmV0dXJuIGV4dGVuZChyZXF1ZXN0T3B0aW9ucywge1xyXG4gICAgYm9keTogZXh0ZW5kKG9wdGlvbnMuYm9keSwgcmVxdWVzdE9wdGlvbnMuYm9keSksXHJcbiAgICBxdWVyeTogZXh0ZW5kKG9wdGlvbnMucXVlcnksIHJlcXVlc3RPcHRpb25zLnF1ZXJ5KSxcclxuICAgIGhlYWRlcnM6IGV4dGVuZChvcHRpb25zLmhlYWRlcnMsIHJlcXVlc3RPcHRpb25zLmhlYWRlcnMpLFxyXG4gICAgb3B0aW9uczogZXh0ZW5kKG9wdGlvbnMub3B0aW9ucywgcmVxdWVzdE9wdGlvbnMub3B0aW9ucylcclxuICB9KTtcclxufVxyXG5cclxuLyoqXHJcbiAqIENvbnN0cnVjdCBhbiBvYmplY3QgdGhhdCBjYW4gaGFuZGxlIHRoZSBtdWx0aXBsZSBPQXV0aCAyLjAgZmxvd3MuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBvcHRpb25zXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQ2xpZW50T0F1dGgyIHtcclxuICAgIC8vIGNvZGUgOiBDb2RlRmxvdztcclxuICAgICB0b2tlbiA6IFRva2VuRmxvdztcclxuICAgIC8vIG93bmVyIDogT3duZXJGbG93O1xyXG4gICAgLy8gY3JlZGVudGlhbHMgOiBDcmVkZW50aWFsc0Zsb3c7XHJcbiAgICAvLyBqd3QgOiBKd3RCZWFyZXJGbG93O1xyXG4gICAgb3B0aW9ucyA6YW55O1xyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihvcHRpb25zOiBhbnkpXHJcbiAgICB7XHJcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcclxuXHJcbiAgICAgICAgLy8gdGhpcy5jb2RlID0gbmV3IENvZGVGbG93KHRoaXMpO1xyXG4gICAgICAgIHRoaXMudG9rZW4gPSBuZXcgVG9rZW5GbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMub3duZXIgPSBuZXcgT3duZXJGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuY3JlZGVudGlhbHMgPSBuZXcgQ3JlZGVudGlhbHNGbG93KHRoaXMpO1xyXG4gICAgICAgIC8vIHRoaXMuand0ID0gbmV3IEp3dEJlYXJlckZsb3codGhpcyk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBjcmVhdGVUb2tlbihhY2Nlc3M6IHN0cmluZywgcmVmcmVzaDogc3RyaW5nLCB0eXBlOiBzdHJpbmcsIGRhdGE6IGFueSlcclxuICAgIHtcclxuICAgICAgICB2YXIgb3B0aW9ucyA9IGV4dGVuZChcclxuICAgICAgICAgICAgZGF0YSxcclxuICAgICAgICAgICAgdHlwZW9mIGFjY2VzcyA9PT0gJ3N0cmluZycgPyB7IGFjY2Vzc190b2tlbjogYWNjZXNzIH0gOiBhY2Nlc3MsXHJcbiAgICAgICAgICAgIHR5cGVvZiByZWZyZXNoID09PSAnc3RyaW5nJyA/IHsgcmVmcmVzaF90b2tlbjogcmVmcmVzaCB9IDogcmVmcmVzaCxcclxuICAgICAgICAgICAgdHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnID8geyB0b2tlbl90eXBlOiB0eXBlIH0gOiB0eXBlXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLCBvcHRpb25zKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIF9yZXF1ZXN0KHJlcXVlc3RPYmplY3QgOiBSZXF1ZXN0T3B0aW9ucykgOmFueSBcclxuICAgIHtcclxuICAgICAgICBsZXQgcmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJlcXVlc3Qub3BlbihyZXF1ZXN0T2JqZWN0Lm1ldGhvZCwgcmVxdWVzdE9iamVjdC51cmwsIGZhbHNlKTtcclxuICAgICAgICBcclxuICAgICAgICBsZXQgaGVhZGVycyA9IHJlcXVlc3RPYmplY3QuaGVhZGVycztcclxuICAgICAgICBmb3IobGV0IGhlYWRlciBpbiBoZWFkZXJzKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKGhlYWRlciwgaGVhZGVyc1toZWFkZXJdKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmVxdWVzdC5zZW5kKHJlcXVlc3RPYmplY3QuYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJlcXVlc3QucmVzcG9uc2U7XHJcbiAgICAgICAgXHJcbiAgICAvLyAgIHJldHVybiB0aGlzLnJlcXVlc3QocmVxdWVzdE9iamVjdClcclxuICAgIC8vICAgICAudGhlbihmdW5jdGlvbiAocmVzKSB7XHJcbiAgICAvLyAgICAgICBpZiAocmVzLnN0YXR1cyA8IDIwMCB8fCByZXMuc3RhdHVzID49IDM5OSkge1xyXG4gICAgLy8gICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKCdIVFRQIHN0YXR1cyAnICsgcmVzLnN0YXR1cylcclxuICAgIC8vICAgICAgICAgZXJyLnN0YXR1cyA9IHJlcy5zdGF0dXNcclxuICAgIC8vICAgICAgICAgZXJyLmJvZHkgPSByZXMuYm9keVxyXG4gICAgLy8gICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKVxyXG4gICAgLy8gICAgICAgfVxyXG5cclxuICAgIC8vICAgICAgIHJldHVybiByZXNcclxuICAgIC8vICAgICB9KVxyXG4gICAgfVxyXG59XHJcblxyXG4vKipcclxuICogQWxpYXMgdGhlIHRva2VuIGNvbnN0cnVjdG9yLlxyXG4gKlxyXG4gKiBAdHlwZSB7RnVuY3Rpb259XHJcbiAqL1xyXG4vL0NsaWVudE9BdXRoMi5Ub2tlbiA9IENsaWVudE9BdXRoMlRva2VuXHJcblxyXG5cclxuLyoqXHJcbiAqIFVzaW5nIHRoZSBidWlsdC1pbiByZXF1ZXN0IG1ldGhvZCwgd2UnbGwgYXV0b21hdGljYWxseSBhdHRlbXB0IHRvIHBhcnNlXHJcbiAqIHRoZSByZXNwb25zZS5cclxuICpcclxuICogQHBhcmFtICB7T2JqZWN0fSAgcmVxdWVzdE9iamVjdFxyXG4gKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4gKi9cclxuXHJcblxyXG4vLyAvKipcclxuLy8gICogU2V0IGBwb3BzaWNsZWAgYXMgdGhlIGRlZmF1bHQgcmVxdWVzdCBtZXRob2QuXHJcbi8vICAqL1xyXG4vLyBDbGllbnRPQXV0aDIucHJvdG90eXBlLnJlcXVlc3QgPSBwb3BzaWNsZS5yZXF1ZXN0XHJcblxyXG4vKipcclxuICogR2VuZXJhbCBwdXJwb3NlIGNsaWVudCB0b2tlbiBnZW5lcmF0b3IuXHJcbiAqXHJcbiAqIEBwYXJhbSB7T2JqZWN0fSBjbGllbnRcclxuICogQHBhcmFtIHtPYmplY3R9IGRhdGFcclxuICovXHJcbmV4cG9ydCBjbGFzcyBDbGllbnRPQXV0aDJUb2tlblxyXG57IFxyXG4gICAgY2xpZW50IDpDbGllbnRPQXV0aDI7XHJcbiAgICBkYXRhIDphbnk7XHJcbiAgICB0b2tlblR5cGUgOnN0cmluZztcclxuICAgIHJlZnJlc2hUb2tlbiA6c3RyaW5nO1xyXG4gICAgZXhwaXJlcyA6RGF0ZTtcclxuICAgIGlkZW50aXR5VG9rZW46IHN0cmluZztcclxuICAgIFxyXG4gICAgX2FjY2Vzc1Rva2VuIDpzdHJpbmc7XHJcbiAgICBcclxuICAgIFxyXG4gICAgZ2V0IGFjY2Vzc1Rva2VuKCkgOnN0cmluZ1xyXG4gICAge1xyXG4gICAgICAgIGlmKHRoaXMuZXhwaXJlZClcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaCgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY2Vzc1Rva2VuO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBzZXQgYWNjZXNzVG9rZW4odmFsdWU6c3RyaW5nKSBcclxuICAgIHtcclxuICAgICAgICB0aGlzLl9hY2Nlc3NUb2tlbiA9IHZhbHVlO1xyXG4gICAgfVxyXG4gICAgXHJcblxyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihjbGllbnQsIGRhdGEpIHtcclxuICAgICAgICB0aGlzLmNsaWVudCA9IGNsaWVudDtcclxuICAgICAgICB0aGlzLmRhdGEgPSBkYXRhO1xyXG4gICAgICAgIHRoaXMudG9rZW5UeXBlID0gZGF0YS50b2tlbl90eXBlICYmIGRhdGEudG9rZW5fdHlwZS50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICAgIHRoaXMuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbiA9IGRhdGEucmVmcmVzaF90b2tlbjtcclxuICAgICAgICB0aGlzLmlkZW50aXR5VG9rZW4gPSBkYXRhLmlkX3Rva2VuO1xyXG5cclxuICAgICAgICB0aGlzLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBcclxuICAgIHB1YmxpYyBleHBpcmVzSW4oZHVyYXRpb24pXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKCFpc05hTihkdXJhdGlvbikpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMuc2V0U2Vjb25kcyh0aGlzLmV4cGlyZXMuZ2V0U2Vjb25kcygpICsgZHVyYXRpb24pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBlbHNlXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLmV4cGlyZXMgPSB1bmRlZmluZWQ7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0aGlzLmV4cGlyZXM7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBzaWduKHJlcXVlc3RPYmplY3QpIHtcclxuICAgICAgICBpZiAoIXRoaXMuYWNjZXNzVG9rZW4pIHtcclxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gc2lnbiB3aXRob3V0IGFjY2VzcyB0b2tlbicpXHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMgPSByZXF1ZXN0T2JqZWN0LmhlYWRlcnMgfHwge31cclxuXHJcbiAgICAgICAgaWYgKHRoaXMudG9rZW5UeXBlID09PSAnYmVhcmVyJykge1xyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LmhlYWRlcnMuQXV0aG9yaXphdGlvbiA9ICdCZWFyZXIgJyArIHRoaXMuYWNjZXNzVG9rZW47XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdmFyIHBhcnRzID0gcmVxdWVzdE9iamVjdC51cmwuc3BsaXQoJyMnKTtcclxuICAgICAgICAgICAgdmFyIHRva2VuID0gJ2FjY2Vzc190b2tlbj0nICsgdGhpcy5hY2Nlc3NUb2tlbjtcclxuICAgICAgICAgICAgdmFyIHVybCA9IHBhcnRzWzBdLnJlcGxhY2UoL1s/Jl1hY2Nlc3NfdG9rZW49W14mI10vLCAnJyk7XHJcbiAgICAgICAgICAgIHZhciBmcmFnbWVudCA9IHBhcnRzWzFdID8gJyMnICsgcGFydHNbMV0gOiAnJztcclxuXHJcbiAgICAgICAgICAgIC8vIFByZXBlbmQgdGhlIGNvcnJlY3QgcXVlcnkgc3RyaW5nIHBhcmFtZXRlciB0byB0aGUgdXJsLlxyXG4gICAgICAgICAgICByZXF1ZXN0T2JqZWN0LnVybCA9IHVybCArICh1cmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPycpICsgdG9rZW4gKyBmcmFnbWVudDtcclxuXHJcbiAgICAgICAgICAgIC8vIEF0dGVtcHQgdG8gYXZvaWQgc3RvcmluZyB0aGUgdXJsIGluIHByb3hpZXMsIHNpbmNlIHRoZSBhY2Nlc3MgdG9rZW5cclxuICAgICAgICAgICAgLy8gaXMgZXhwb3NlZCBpbiB0aGUgcXVlcnkgcGFyYW1ldGVycy5cclxuICAgICAgICAgICAgcmVxdWVzdE9iamVjdC5oZWFkZXJzLlByYWdtYSA9ICduby1zdG9yZSc7XHJcbiAgICAgICAgICAgIHJlcXVlc3RPYmplY3QuaGVhZGVyc1snQ2FjaGUtQ29udHJvbCddID0gJ25vLXN0b3JlJztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiByZXF1ZXN0T2JqZWN0O1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgcmVxdWVzdChvcHRpb25zKSB7XHJcbiAgICAgICAgbGV0IHJlcXVlc3RPcHRpb25zUmVzdWx0ID0gcmVxdWVzdE9wdGlvbnModGhpcy5zaWduKG9wdGlvbnMpLCB0aGlzLmNsaWVudC5vcHRpb25zKTtcclxuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnNSZXN1bHQpO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBcclxuICAgIHB1YmxpYyByZWZyZXNoKG9wdGlvbnM/KTphbnkge1xyXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcclxuXHJcbiAgICAgICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKTtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLnJlZnJlc2hUb2tlbikge1xyXG4gICAgICAgICAgICByZXR1cm4gbmV3IEVycm9yKCdObyByZWZyZXNoIHRva2VuIHNldCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4gICAgICAgICAgICB1cmw6IG9wdGlvbnMuYWNjZXNzVG9rZW5VcmksXHJcbiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4gICAgICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbiAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICBib2R5OiB7XHJcbiAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxyXG4gICAgICAgICAgICBncmFudF90eXBlOiAncmVmcmVzaF90b2tlbidcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0sIG9wdGlvbnMpKTtcclxuICAgICAgICBcclxuICAgICAgICBcclxuICAgICAgICBsZXQgYm9keSA9IGhhbmRsZUF1dGhSZXNwb25zZShyZXNwb25zZSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgLy9UT0RPOiBUcmF0YXIgcXVhbmRvIGV4Y2VwdGlvblxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZXRvcm5vID0gKGZ1bmN0aW9uIChkYXRhKSB7XHJcbiAgICAgICAgICAgIHNlbGYuYWNjZXNzVG9rZW4gPSBkYXRhLmFjY2Vzc190b2tlbjtcclxuICAgICAgICAgICAgc2VsZi5yZWZyZXNoVG9rZW4gPSBkYXRhLnJlZnJlc2hfdG9rZW47XHJcblxyXG4gICAgICAgICAgICBzZWxmLmV4cGlyZXNJbihkYXRhLmV4cGlyZXNfaW4pO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHNlbGY7XHJcbiAgICAgICAgfSkoYm9keSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHJldG9ybm87XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGdldCBleHBpcmVkKCkgOiBib29sZWFuXHJcbiAgICB7XHJcbiAgICAgICAgaWYgKHRoaXMuZXhwaXJlcykge1xyXG4gICAgICAgICAgICByZXR1cm4gRGF0ZS5ub3coKSA+IHRoaXMuZXhwaXJlcy5nZXRUaW1lKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBcclxuICAgICAgICAgXHJcblxyXG4gICAgICAgIFxyXG59XHJcblxyXG5cclxuXHJcblxyXG5cclxuXHJcblxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCByZXNvdXJjZSBvd25lciBwYXNzd29yZCBjcmVkZW50aWFscyBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuM1xyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBPd25lckZsb3cgKGNsaWVudCkge1xyXG4vLyAgIHRoaXMuY2xpZW50ID0gY2xpZW50XHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBNYWtlIGEgcmVxdWVzdCBvbiBiZWhhbGYgb2YgdGhlIHVzZXIgY3JlZGVudGlhbHMgdG8gZ2V0IGFuIGFjY2VzIHRva2VuLlxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICB1c2VybmFtZVxyXG4vLyAgKiBAcGFyYW0gIHtTdHJpbmd9ICBwYXNzd29yZFxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gT3duZXJGbG93LnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1c2VybmFtZSwgcGFzc3dvcmQsIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICB1c2VybmFtZTogdXNlcm5hbWUsXHJcbi8vICAgICAgIHBhc3N3b3JkOiBwYXNzd29yZCxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ3Bhc3N3b3JkJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBGbG93XHJcbntcclxuICAgIGNsaWVudDogQ2xpZW50T0F1dGgyO1xyXG4gICAgXHJcbiAgICBjb25zdHJ1Y3RvcihjbGllbnQpIHtcclxuICAgICAgICB0aGlzLmNsaWVudCA9IGNsaWVudDtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcHVibGljIGdldFVzZXJJbmZvKGFjY2Vzc1Rva2VuOiBzdHJpbmcpIDogVXNlckluZm9SZXNwb25zZVxyXG4gICAge1xyXG4gICAgICAgIGxldCByZXNwb25zZSA9IHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuICAgICAgICB1cmw6IHRoaXMuY2xpZW50Lm9wdGlvbnMudXNlckluZm9VcmksXHJcbiAgICAgICAgbWV0aG9kOiAnR0VUJyxcclxuICAgICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbiAgICAgICAgICAgIEF1dGhvcml6YXRpb246ICdCZWFyZXIgJyArIGFjY2Vzc1Rva2VuXHJcbiAgICAgICAgfSlcclxuICAgICAgICB9LCB0aGlzLmNsaWVudC5vcHRpb25zKSk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlSlNPTiA9IEpTT04ucGFyc2UocmVzcG9uc2UpO1xyXG4gICAgICAgIGxldCB1c2VySW5mb1Jlc3BvbnNlID0gbmV3IFVzZXJJbmZvUmVzcG9uc2UocmVzcG9uc2VKU09OLnN1Yik7XHJcbiAgICAgICAgdXNlckluZm9SZXNwb25zZSA9IGV4dGVuZCh1c2VySW5mb1Jlc3BvbnNlLCByZXNwb25zZUpTT04pO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiB1c2VySW5mb1Jlc3BvbnNlO1xyXG4gICAgfVxyXG59XHJcblxyXG4vKipcclxuICogU3VwcG9ydCBpbXBsaWNpdCBPQXV0aCAyLjAgZ3JhbnQuXHJcbiAqXHJcbiAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMlxyXG4gKlxyXG4gKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgVG9rZW5GbG93IGV4dGVuZHMgRmxvd1xyXG57XHJcbiAgICBwdWJsaWMgZ2V0VXJpKG9wdGlvbnM/OmFueSkge1xyXG4gICAgICAgIG9wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcbiAgICAgICAgcmV0dXJuIGNyZWF0ZVVyaShvcHRpb25zLCAndG9rZW4nKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0VG9rZW4odXJpLCBzdGF0ZT8sIG9wdGlvbnM/KSBcclxuICAgIHtcclxuICAgICAgICAvL29wdGlvbnMgPSBleHRlbmQodGhpcy5jbGllbnQub3B0aW9ucywgb3B0aW9ucyk7XHJcblxyXG4gICAgICAgIC8vIHZhciB1cmwgPSBwYXJzZVVybCh1cmkpXHJcbiAgICAgICAgLy8gdmFyIGV4cGVjdGVkVXJsID0gcGFyc2VVcmwob3B0aW9ucy5yZWRpcmVjdFVyaSlcclxuXHJcbiAgICAgICAgLy8gaWYgKHVybC5wYXRobmFtZSAhPT0gZXhwZWN0ZWRVcmwucGF0aG5hbWUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1Nob3VsZCBtYXRjaCByZWRpcmVjdCB1cmk6ICcgKyB1cmkpKVxyXG4gICAgICAgIC8vIH1cclxuXHJcbiAgICAgICAgLy8gLy8gSWYgbm8gcXVlcnkgc3RyaW5nIG9yIGZyYWdtZW50IGV4aXN0cywgd2Ugd29uJ3QgYmUgYWJsZSB0byBwYXJzZVxyXG4gICAgICAgIC8vIC8vIGFueSB1c2VmdWwgaW5mb3JtYXRpb24gZnJvbSB0aGUgdXJpLlxyXG4gICAgICAgIC8vIGlmICghdXJsLmhhc2ggJiYgIXVybC5zZWFyY2gpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ1VuYWJsZSB0byBwcm9jZXNzIHVyaTogJyArIHVyaSkpXHJcbiAgICAgICAgLy8gfVxyXG5cclxuICAgICAgICAvLyBFeHRyYWN0IGRhdGEgZnJvbSBib3RoIHRoZSBmcmFnbWVudCBhbmQgcXVlcnkgc3RyaW5nLiBUaGUgZnJhZ21lbnQgaXMgbW9zdFxyXG4gICAgICAgIC8vIGltcG9ydGFudCwgYnV0IHRoZSBxdWVyeSBzdHJpbmcgaXMgYWxzbyB1c2VkIGJlY2F1c2Ugc29tZSBPQXV0aCAyLjBcclxuICAgICAgICAvLyBpbXBsZW1lbnRhdGlvbnMgKEluc3RhZ3JhbSkgaGF2ZSBhIGJ1ZyB3aGVyZSBzdGF0ZSBpcyBwYXNzZWQgdmlhIHF1ZXJ5LlxyXG4gICAgICAgIC8vIHZhciBkYXRhID0gZXh0ZW5kKFxyXG4gICAgICAgIC8vICAgICB1cmwucXVlcnkgPyBwYXJzZVF1ZXJ5KHVybC5xdWVyeSkgOiB7fSxcclxuICAgICAgICAvLyAgICAgdXJsLmhhc2ggPyBwYXJzZVF1ZXJ5KHVybC5oYXNoLnN1YnN0cigxKSkgOiB7fVxyXG4gICAgICAgIC8vIClcclxuXHJcbiAgICAgICAgLy8gdmFyIGVyciA9IGdldEF1dGhFcnJvcihkYXRhKVxyXG5cclxuICAgICAgICAvLyAvLyBDaGVjayBpZiB0aGUgcXVlcnkgc3RyaW5nIHdhcyBwb3B1bGF0ZWQgd2l0aCBhIGtub3duIGVycm9yLlxyXG4gICAgICAgIC8vIGlmIChlcnIpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycilcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIC8vIC8vIENoZWNrIHdoZXRoZXIgdGhlIHN0YXRlIG1hdGNoZXMuXHJcbiAgICAgICAgLy8gaWYgKHN0YXRlICE9IG51bGwgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuICAgICAgICAvLyAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgc3RhdGU6ICcgKyBkYXRhLnN0YXRlKSlcclxuICAgICAgICAvLyB9XHJcblxyXG4gICAgICAgIGZ1bmN0aW9uIFBhcnNlYXJVcmwodXJsOiBzdHJpbmcpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBpZih1cmwuaW5kZXhPZignIycpICE9PSAtMSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHVybC5zdWJzdHIodXJsLmluZGV4T2YoJyMnKSx1cmwubGVuZ3RoKS5yZXBsYWNlKCc/JywnJykucmVwbGFjZSgnIycsJycpLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uKHMsYyl7dmFyIHQ9Yy5zcGxpdCgnPScpO3NbdFswXV09dFsxXTtyZXR1cm4gczt9LHt9KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB1cmwuc3Vic3RyKHVybC5pbmRleE9mKCc/JyksdXJsLmxlbmd0aCkucmVwbGFjZSgnPycsJycpLnJlcGxhY2UoJyMnLCcnKS5zcGxpdCgnJicpLnJlZHVjZShmdW5jdGlvbihzLGMpe3ZhciB0PWMuc3BsaXQoJz0nKTtzW3RbMF1dPXRbMV07cmV0dXJuIHM7fSx7fSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCB1cmxQYXJzZWFkYSA9IFBhcnNlYXJVcmwodXJpKTtcclxuXHJcbiAgICAgICAgbGV0IGRhdGEgPSB1cmxQYXJzZWFkYTtcclxuXHJcbiAgICAgICAgLy8gSW5pdGFsaXplIGEgbmV3IHRva2VuIGFuZCByZXR1cm4uXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbih0aGlzLmNsaWVudCwgZGF0YSk7XHJcbiAgICB9XHJcbiAgIFxyXG59XHJcbiAgICBcclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIENsYWltYWJsZVxyXG57XHJcbiAgICBnZXRDbGFpbShjbGFpbU5hbWU6IHN0cmluZylcclxuICAgIHtcclxuICAgICAgICByZXR1cm4gKDxhbnk+dGhpcylbY2xhaW1OYW1lXTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIFVzZXJJbmZvUmVzcG9uc2UgZXh0ZW5kcyBDbGFpbWFibGVcclxue1xyXG4gICAgY29uc3RydWN0b3IocHVibGljIHN1YjpzdHJpbmcpIFxyXG4gICAge1xyXG4gICAgICAgIHN1cGVyKCk7XHJcbiAgICB9XHJcbn1cclxuICAgIFxyXG4vLyAvKipcclxuLy8gICogU3VwcG9ydCBjbGllbnQgY3JlZGVudGlhbHMgT0F1dGggMi4wIGdyYW50LlxyXG4vLyAgKlxyXG4vLyAgKiBSZWZlcmVuY2U6IGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi00LjRcclxuLy8gICpcclxuLy8gICogQHBhcmFtIHtDbGllbnRPQXV0aDJ9IGNsaWVudFxyXG4vLyAgKi9cclxuLy8gZnVuY3Rpb24gQ3JlZGVudGlhbHNGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgdGhlIGNsaWVudCBjcmVkZW50aWFscy5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDcmVkZW50aWFsc0Zsb3cucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdjbGllbnRJZCcsXHJcbi8vICAgICAnY2xpZW50U2VjcmV0JyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICByZXR1cm4gdGhpcy5jbGllbnQuX3JlcXVlc3QocmVxdWVzdE9wdGlvbnMoe1xyXG4vLyAgICAgdXJsOiBvcHRpb25zLmFjY2Vzc1Rva2VuVXJpLFxyXG4vLyAgICAgbWV0aG9kOiAnUE9TVCcsXHJcbi8vICAgICBoZWFkZXJzOiBleHRlbmQoREVGQVVMVF9IRUFERVJTLCB7XHJcbi8vICAgICAgIEF1dGhvcml6YXRpb246IGF1dGgob3B0aW9ucy5jbGllbnRJZCwgb3B0aW9ucy5jbGllbnRTZWNyZXQpXHJcbi8vICAgICB9KSxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAnY2xpZW50X2NyZWRlbnRpYWxzJ1xyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IGF1dGhvcml6YXRpb24gY29kZSBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTQuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBDb2RlRmxvdyAoY2xpZW50KSB7XHJcbi8vICAgdGhpcy5jbGllbnQgPSBjbGllbnRcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdlbmVyYXRlIHRoZSB1cmkgZm9yIGRvaW5nIHRoZSBmaXJzdCByZWRpcmVjdC5cclxuLy8gICpcclxuLy8gICogQHJldHVybiB7U3RyaW5nfVxyXG4vLyAgKi9cclxuLy8gQ29kZUZsb3cucHJvdG90eXBlLmdldFVyaSA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICByZXR1cm4gY3JlYXRlVXJpKG9wdGlvbnMsICdjb2RlJylcclxuLy8gfVxyXG5cclxuLy8gLyoqXHJcbi8vICAqIEdldCB0aGUgY29kZSB0b2tlbiBmcm9tIHRoZSByZWRpcmVjdGVkIHVyaSBhbmQgbWFrZSBhbm90aGVyIHJlcXVlc3QgZm9yXHJcbi8vICAqIHRoZSB1c2VyIGFjY2VzcyB0b2tlbi5cclxuLy8gICpcclxuLy8gICogQHBhcmFtICB7U3RyaW5nfSAgdXJpXHJcbi8vICAqIEBwYXJhbSAge1N0cmluZ30gIFtzdGF0ZV1cclxuLy8gICogQHBhcmFtICB7T2JqZWN0fSAgW29wdGlvbnNdXHJcbi8vICAqIEByZXR1cm4ge1Byb21pc2V9XHJcbi8vICAqL1xyXG4vLyBDb2RlRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJpLCBzdGF0ZSwgb3B0aW9ucykge1xyXG4vLyAgIHZhciBzZWxmID0gdGhpc1xyXG5cclxuLy8gICBvcHRpb25zID0gZXh0ZW5kKHRoaXMuY2xpZW50Lm9wdGlvbnMsIG9wdGlvbnMpXHJcblxyXG4vLyAgIGV4cGVjdHMob3B0aW9ucywgW1xyXG4vLyAgICAgJ2NsaWVudElkJyxcclxuLy8gICAgICdjbGllbnRTZWNyZXQnLFxyXG4vLyAgICAgJ3JlZGlyZWN0VXJpJyxcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgdXJsID0gcGFyc2VVcmwodXJpKVxyXG4vLyAgIHZhciBleHBlY3RlZFVybCA9IHBhcnNlVXJsKG9wdGlvbnMucmVkaXJlY3RVcmkpXHJcblxyXG4vLyAgIGlmICh1cmwucGF0aG5hbWUgIT09IGV4cGVjdGVkVXJsLnBhdGhuYW1lKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignU2hvdWxkIG1hdGNoIHJlZGlyZWN0IHVyaTogJyArIHVyaSkpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoIXVybC5zZWFyY2gpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdVbmFibGUgdG8gcHJvY2VzcyB1cmk6ICcgKyB1cmkpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgdmFyIGRhdGEgPSBwYXJzZVF1ZXJ5KHVybC5xdWVyeSlcclxuLy8gICB2YXIgZXJyID0gZ2V0QXV0aEVycm9yKGRhdGEpXHJcblxyXG4vLyAgIGlmIChlcnIpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpXHJcbi8vICAgfVxyXG5cclxuLy8gICBpZiAoc3RhdGUgJiYgZGF0YS5zdGF0ZSAhPT0gc3RhdGUpIHtcclxuLy8gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgVHlwZUVycm9yKCdJbnZhbGlkIHN0YXRlOicgKyBkYXRhLnN0YXRlKSlcclxuLy8gICB9XHJcblxyXG4vLyAgIC8vIENoZWNrIHdoZXRoZXIgdGhlIHJlc3BvbnNlIGNvZGUgaXMgc2V0LlxyXG4vLyAgIGlmICghZGF0YS5jb2RlKSB7XHJcbi8vICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFR5cGVFcnJvcignTWlzc2luZyBjb2RlLCB1bmFibGUgdG8gcmVxdWVzdCB0b2tlbicpKVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogZXh0ZW5kKERFRkFVTFRfSEVBREVSUyksXHJcbi8vICAgICBib2R5OiB7XHJcbi8vICAgICAgIGNvZGU6IGRhdGEuY29kZSxcclxuLy8gICAgICAgZ3JhbnRfdHlwZTogJ2F1dGhvcml6YXRpb25fY29kZScsXHJcbi8vICAgICAgIHJlZGlyZWN0X3VyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcclxuLy8gICAgICAgY2xpZW50X2lkOiBvcHRpb25zLmNsaWVudElkLFxyXG4vLyAgICAgICBjbGllbnRfc2VjcmV0OiBvcHRpb25zLmNsaWVudFNlY3JldFxyXG4vLyAgICAgfVxyXG4vLyAgIH0sIG9wdGlvbnMpKVxyXG4vLyAgICAgLnRoZW4oaGFuZGxlQXV0aFJlc3BvbnNlKVxyXG4vLyAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcclxuLy8gICAgICAgcmV0dXJuIG5ldyBDbGllbnRPQXV0aDJUb2tlbihzZWxmLmNsaWVudCwgZGF0YSlcclxuLy8gICAgIH0pXHJcbi8vIH1cclxuXHJcbi8vIC8qKlxyXG4vLyAgKiBTdXBwb3J0IEpTT04gV2ViIFRva2VuIChKV1QpIEJlYXJlciBUb2tlbiBPQXV0aCAyLjAgZ3JhbnQuXHJcbi8vICAqXHJcbi8vICAqIFJlZmVyZW5jZTogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL2RyYWZ0LWlldGYtb2F1dGgtand0LWJlYXJlci0xMiNzZWN0aW9uLTIuMVxyXG4vLyAgKlxyXG4vLyAgKiBAcGFyYW0ge0NsaWVudE9BdXRoMn0gY2xpZW50XHJcbi8vICAqL1xyXG4vLyBmdW5jdGlvbiBKd3RCZWFyZXJGbG93IChjbGllbnQpIHtcclxuLy8gICB0aGlzLmNsaWVudCA9IGNsaWVudFxyXG4vLyB9XHJcblxyXG4vLyAvKipcclxuLy8gICogUmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gdXNpbmcgYSBKV1QgdG9rZW4uXHJcbi8vICAqXHJcbi8vICAqIEBwYXJhbSAge3N0cmluZ30gdG9rZW4gQSBKV1QgdG9rZW4uXHJcbi8vICAqIEBwYXJhbSAge09iamVjdH0gIFtvcHRpb25zXVxyXG4vLyAgKiBAcmV0dXJuIHtQcm9taXNlfVxyXG4vLyAgKi9cclxuLy8gSnd0QmVhcmVyRmxvdy5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodG9rZW4sIG9wdGlvbnMpIHtcclxuLy8gICB2YXIgc2VsZiA9IHRoaXNcclxuXHJcbi8vICAgb3B0aW9ucyA9IGV4dGVuZCh0aGlzLmNsaWVudC5vcHRpb25zLCBvcHRpb25zKVxyXG5cclxuLy8gICBleHBlY3RzKG9wdGlvbnMsIFtcclxuLy8gICAgICdhY2Nlc3NUb2tlblVyaSdcclxuLy8gICBdKVxyXG5cclxuLy8gICB2YXIgaGVhZGVycyA9IGV4dGVuZChERUZBVUxUX0hFQURFUlMpXHJcblxyXG4vLyAgIC8vIEF1dGhlbnRpY2F0aW9uIG9mIHRoZSBjbGllbnQgaXMgb3B0aW9uYWwsIGFzIGRlc2NyaWJlZCBpblxyXG4vLyAgIC8vIFNlY3Rpb24gMy4yLjEgb2YgT0F1dGggMi4wIFtSRkM2NzQ5XVxyXG4vLyAgIGlmIChvcHRpb25zLmNsaWVudElkKSB7XHJcbi8vICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBhdXRoKG9wdGlvbnMuY2xpZW50SWQsIG9wdGlvbnMuY2xpZW50U2VjcmV0KVxyXG4vLyAgIH1cclxuXHJcbi8vICAgcmV0dXJuIHRoaXMuY2xpZW50Ll9yZXF1ZXN0KHJlcXVlc3RPcHRpb25zKHtcclxuLy8gICAgIHVybDogb3B0aW9ucy5hY2Nlc3NUb2tlblVyaSxcclxuLy8gICAgIG1ldGhvZDogJ1BPU1QnLFxyXG4vLyAgICAgaGVhZGVyczogaGVhZGVycyxcclxuLy8gICAgIGJvZHk6IHtcclxuLy8gICAgICAgc2NvcGU6IHNhbml0aXplU2NvcGUob3B0aW9ucy5zY29wZXMpLFxyXG4vLyAgICAgICBncmFudF90eXBlOiAndXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlcicsXHJcbi8vICAgICAgIGFzc2VydGlvbjogdG9rZW5cclxuLy8gICAgIH1cclxuLy8gICB9LCBvcHRpb25zKSlcclxuLy8gICAgIC50aGVuKGhhbmRsZUF1dGhSZXNwb25zZSlcclxuLy8gICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XHJcbi8vICAgICAgIHJldHVybiBuZXcgQ2xpZW50T0F1dGgyVG9rZW4oc2VsZi5jbGllbnQsIGRhdGEpXHJcbi8vICAgICB9KVxyXG4vLyB9XHJcbiJdfQ==
