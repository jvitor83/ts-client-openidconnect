declare var extend: any;
declare var popsicle: any;
declare var parseQuery: any;
declare var parseUrl: any;
declare var btoa: typeof btoaBuffer;




declare class Promise {
    constructor(promise: any);
    then(successCallback?: (value?: any) => void, errorCallback?: (reason?: any) => void): Promise;
    catch(errorCallback: () => void): Promise;
}

declare class PromiseFactory {
    resolve(value: any): Promise;
    reject(reason: any): Promise;
    create(callback: any): Promise;
}


/**
 * Default headers for executing OAuth 2.0 flows.
 *
 * @type {Object}
 */
declare var DEFAULT_HEADERS: {
    'Accept': string;
    'Content-Type': string;
};
/**
 * Format error response types to regular strings for displaying to clients.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1.2.1
 *
 * @type {Object}
 */
declare var ERROR_RESPONSES: {
    'invalid_request': string;
    'invalid_client': string;
    'invalid_grant': string;
    'unauthorized_client': string;
    'unsupported_grant_type': string;
    'access_denied': string;
    'unsupported_response_type': string;
    'invalid_scope': string;
    'server_error': string;
    'temporarily_unavailable': string;
};
/**
 * Support base64 in node like how it works in the browser.
 *
 * @param  {String} string
 * @return {String}
 */
declare function btoaBuffer(string: any): any;
/**
 * Check if properties exist on an object and throw when they aren't.
 *
 * @throws {TypeError} If an expected property is missing.
 *
 * @param {Object} obj
 * @param {Array}  props
 */
declare function expects(obj: any, props: any): void;
/**
 * Pull an authentication error from the response data.
 *
 * @param  {Object} data
 * @return {String}
 */
declare function getAuthError(data: any): Error;
/**
 * Handle the authentication response object.
 *
 * @param  {Object}  res
 * @return {Promise}
 */
declare function handleAuthResponse(res: any): any;
/**
 * Sanitize the scopes option to be a string.
 *
 * @param  {Array}  scopes
 * @return {String}
 */
declare function sanitizeScope(scopes: any): any;
/**
 * Create a request uri based on an options object and token type.
 *
 * @param  {Object} options
 * @param  {String} tokenType
 * @return {String}
 */
declare function createUri(options: any, tokenType: any): string;
/**
 * Create basic auth header.
 *
 * @param  {String} username
 * @param  {String} password
 * @return {String}
 */
declare function auth(username: any, password: any): string;
/**
 * Ensure a value is a string.
 *
 * @param  {String} str
 * @return {String}
 */
declare function string(str: any): string;
/**
 * Merge request options from an options object.
 */
declare function requestOptions(requestOptions: any, options: any): any;
/**
 * Construct an object that can handle the multiple OAuth 2.0 flows.
 *
 * @param {Object} options
 */
declare class ClientOAuth2{
    constructor(options: any);
    createToken(access: string, refresh: string, type: string, data: any);
    
    code : CodeFlow;
    token : TokenFlow;
    owner : OwnerFlow;
    credentials : CredentialsFlow;
    jwt : JwtBearerFlow;
    
}
/**
 * General purpose client token generator.
 *
 * @param {Object} client
 * @param {Object} data
 */
declare class ClientOAuth2Token{
    constructor(client: string, data: any);
    expiresIn(duration: Number): Date;
    request(options: any): Promise;
    refresh(options: any): Promise;
    expired(): boolean;
    data: any;
    accessToken: string;
    refreshToken: string;
    tokenType: string;
    client: ClientOAuth2;
}
/**
 * Support resource owner password credentials OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.3
 *
 * @param {ClientOAuth2} client
 */
declare class OwnerFlow
{
    constructor(client: any);
    getToken(username:string, password:string, options:any): Promise;
}
/**
 * Support implicit OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
 *
 * @param {ClientOAuth2} client
 */
declare class TokenFlow
{
    constructor(client: any);
    getUri(options?: any):string;
    getToken(uri:string, state?:string, options?:any): Promise;
    
    
}
/**
 * Support client credentials OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.4
 *
 * @param {ClientOAuth2} client
 */
declare class CredentialsFlow{
    constructor(client: any);
    getToken(options?: any): Promise;
    
    
}

/**
 * Support authorization code OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1
 *
 * @param {ClientOAuth2} client
 */
declare class CodeFlow
{
    constructor(client: any);
    getUri(options?:any):string;
    getToken(uri:string, state?:string, options?:any):Promise;
}
/**
 * Support JSON Web Token (JWT) Bearer Token OAuth 2.0 grant.
 *
 * Reference: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1
 *
 * @param {ClientOAuth2} client
 */
declare class JwtBearerFlow
{
    constructor(client: any);
    getToken(token:string, options?: any): Promise;
}
