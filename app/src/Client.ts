// import 'xtend';
// import 'popsicle';
// import 'querystring';
// import 'url';

var hasOwnProperty = Object.prototype.hasOwnProperty;

var extend = function extend(...args:Array<any>):any {
    var target = {}

    for (var i = 0; i < args.length; i++) {
        var source = args[i]

        for (var key in source) {
            if (hasOwnProperty.call(source, key)) {
                target[key] = source[key]
            }
        }
    }

    return target;
}



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
var DEFAULT_HEADERS = {
  'Accept': 'application/json, application/x-www-form-urlencoded',
  'Content-Type': 'application/x-www-form-urlencoded'
}

/**
 * Format error response types to regular strings for displaying to clients.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1.2.1
 *
 * @type {Object}
 */
var ERROR_RESPONSES = {
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
}


/**
 * Check if properties exist on an object and throw when they aren't.
 *
 * @throws {TypeError} If an expected property is missing.
 *
 * @param {Object} obj
 * @param {Array}  props
 */
function expects (obj, props) {
  for (var i = 0; i < props.length; i++) {
    var prop = props[i]

    if (obj[prop] == null) {
      throw new TypeError('Expected "' + prop + '" to exist')
    }
  }
}

/**
 * Pull an authentication error from the response data.
 *
 * @param  {Object} data
 * @return {String}
 */
function getAuthError (data) {
  var message = ERROR_RESPONSES[data.error] ||
    data.error ||
    data.error_message

  // Return an error instance with the message if it exists.
  return message && new Error(message)
}

/**
 * Handle the authentication response object.
 *
 * @param  {Object}  res
 * @return {Promise}
 */
function handleAuthResponse (res) {
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
function sanitizeScope (scopes) {
  return Array.isArray(scopes) ? scopes.join(' ') : string(scopes);
}

/**
 * Create a request uri based on an options object and token type.
 *
 * @param  {Object} options
 * @param  {String} tokenType
 * @return {String}
 */
function createUri (options, tokenType) {
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
function auth (username, password) {
  return 'Basic ' + btoa(string(username) + ':' + string(password));
}

/**
 * Ensure a value is a string.
 *
 * @param  {String} str
 * @return {String}
 */
function string (str) {
  return str == null ? '' : String(str);
}

export interface RequestOptions {
    body: any;
    query: any;
    headers: any;
    options: any;
    method: string;
    url: string;
};

/**
 * Merge request options from an options object.
 */
function requestOptions (requestOptions, options): RequestOptions {

  return extend(requestOptions, {
    body: extend(options.body, requestOptions.body),
    query: extend(options.query, requestOptions.query),
    headers: extend(options.headers, requestOptions.headers),
    options: extend(options.options, requestOptions.options)
  });
}

/**
 * Construct an object that can handle the multiple OAuth 2.0 flows.
 *
 * @param {Object} options
 */
export class ClientOAuth2 {
    // code : CodeFlow;
     token : TokenFlow;
    // owner : OwnerFlow;
    // credentials : CredentialsFlow;
    // jwt : JwtBearerFlow;
    options :any;
    
    constructor(options: any)
    {
        this.options = options;

        // this.code = new CodeFlow(this);
        this.token = new TokenFlow(this);
        // this.owner = new OwnerFlow(this);
        // this.credentials = new CredentialsFlow(this);
        // this.jwt = new JwtBearerFlow(this);
    }
    
    public createToken(access: string, refresh: string, type: string, data: any)
    {
        var options = extend(
            data,
            typeof access === 'string' ? { access_token: access } : access,
            typeof refresh === 'string' ? { refresh_token: refresh } : refresh,
            typeof type === 'string' ? { token_type: type } : type
        );

        return new ClientOAuth2Token(this, options);
    }
    
    public _request(requestObject : RequestOptions) :any 
    {
        let request = new XMLHttpRequest();
        
        request.open(requestObject.method, requestObject.url, false);
        
        let headers = requestObject.headers;
        for(let header in headers)
        {
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
    }
}

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
export class ClientOAuth2Token
{ 
    client :ClientOAuth2;
    data :any;
    tokenType :string;
    refreshToken :string;
    expires :Date;
    identityToken: string;
    
    _accessToken :string;
    
    
    get accessTokenContent(): any
    {
        let content = this._accessToken.split('.')[1];
        let returnContent = JSON.parse(content);
        return returnContent;
    }
    
    private isAccessTokenExpired()
    {
        let accessTokenContent = this.accessTokenContent;
        
        let accessTokenExp :number = accessTokenContent.exp;
        let expired = accessTokenExp < Math.floor(Date.now() / 1000);
        
        return expired;
    }
    
    get accessToken() :string
    {
        if(this.expired || this.isAccessTokenExpired)
        {
            this.refresh();
        }

        return this._accessToken;
    }
    
    set accessToken(value:string) 
    {
        this._accessToken = value;
    }
    

    
    constructor(client, data) {
        this.client = client;
        this.data = data;
        this.tokenType = data.token_type && data.token_type.toLowerCase();
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        this.identityToken = data.id_token;

        this.expiresIn(data.expires_in);
    }
    
    
    public expiresIn(duration)
    {
        if (!isNaN(duration))
        {
            this.expires = new Date();
            this.expires.setSeconds(this.expires.getSeconds() + duration);
        }
        else
        {
            this.expires = undefined;
        }
        return this.expires;
    }
    
    public sign(requestObject) {
        if (!this.accessToken) {
            throw new Error('Unable to sign without access token')
        }

        requestObject.headers = requestObject.headers || {}

        if (this.tokenType === 'bearer') {
            requestObject.headers.Authorization = 'Bearer ' + this.accessToken;
        } else {
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
    }
    
    public request(options) {
        let requestOptionsResult = requestOptions(this.sign(options), this.client.options);
        return this.client._request(requestOptionsResult);
    }
    
    
    public refresh(options?):any {
        var self = this;

        options = extend(this.client.options, options);

        if (!this.refreshToken) {
            return new Error('No refresh token set');
        }

        
        let response = this.client._request(requestOptions({
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
        
        
        let body = handleAuthResponse(response);
        
        //TODO: Tratar quando exception
        
        let retorno = (function (data) {
            self.accessToken = data.access_token;
            self.refreshToken = data.refresh_token;

            self.expiresIn(data.expires_in);

            return self;
        })(body);
        
        return retorno;
    }
    
    get expired() : boolean
    {
        if (this.expires) {
            return Date.now() > this.expires.getTime();
        }

        return false;
    }
    
         

        
}







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

export abstract class Flow
{
    client: ClientOAuth2;
    
    constructor(client) {
        this.client = client;
    }
    
    public getUserInfo(accessToken: string) : UserInfoResponse
    {
        let response = this.client._request(requestOptions({
        url: this.client.options.userInfoUri,
        method: 'GET',
        headers: extend(DEFAULT_HEADERS, {
            Authorization: 'Bearer ' + accessToken
        })
        }, this.client.options));
        
        
        let responseJSON = JSON.parse(response);
        let userInfoResponse = new UserInfoResponse(responseJSON.sub);
        userInfoResponse = extend(userInfoResponse, responseJSON);
        
        return userInfoResponse;
    }
}

/**
 * Support implicit OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
 *
 * @param {ClientOAuth2} client
 */
export class TokenFlow extends Flow
{
    public getUri(options?:any) {
        options = extend(this.client.options, options);
        return createUri(options, 'token');
    }

    public getToken(uri, state?, options?) 
    {
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

        function ParsearUrl(url: string)
        {
            if(url.indexOf('#') !== -1)
            {
                return url.substr(url.indexOf('#'),url.length).replace('?','').replace('#','').split('&').reduce(function(s,c){var t=c.split('=');s[t[0]]=t[1];return s;},{});
            }
            else
            {
                return url.substr(url.indexOf('?'),url.length).replace('?','').replace('#','').split('&').reduce(function(s,c){var t=c.split('=');s[t[0]]=t[1];return s;},{});
            }
        }

        let urlParseada = ParsearUrl(uri);

        let data = urlParseada;

        // Initalize a new token and return.
        return new ClientOAuth2Token(this.client, data);
    }
   
}
    
export abstract class Claimable
{
    getClaim(claimName: string)
    {
        return (<any>this)[claimName];
    }
}

export class UserInfoResponse extends Claimable
{
    constructor(public sub:string) 
    {
        super();
    }
}
    
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
