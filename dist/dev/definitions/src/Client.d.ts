export interface RequestOptions {
    body: any;
    query: any;
    headers: any;
    options: any;
    method: string;
    url: string;
}
/**
 * Construct an object that can handle the multiple OAuth 2.0 flows.
 *
 * @param {Object} options
 */
export declare class ClientOAuth2 {
    token: TokenFlow;
    options: any;
    constructor(options: any);
    createToken(access: string, refresh: string, type: string, data: any): ClientOAuth2Token;
    _request(requestObject: RequestOptions): any;
}
/**
 * Alias the token constructor.
 *
 * @type {Function}
 */
/**
 * Using the built-in request method, we'll automatically attempt to parse
 * the response.
 *
 * @param  {Object}  requestObject
 * @return {Promise}
 */
/**
 * General purpose client token generator.
 *
 * @param {Object} client
 * @param {Object} data
 */
export declare class ClientOAuth2Token {
    client: ClientOAuth2;
    data: any;
    tokenType: string;
    accessToken: string;
    refreshToken: string;
    expires: Date;
    constructor(client: any, data: any);
    expiresIn(duration: any): Date;
    sign(requestObject: any): any;
    request(options: any): any;
    refresh(options: any): any;
    expired: boolean;
}
/**
 * Support implicit OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
 *
 * @param {ClientOAuth2} client
 */
export declare class TokenFlow {
    client: ClientOAuth2;
    constructor(client: any);
    getUri(options?: any): string;
    getToken(uri: any, state?: any, options?: any): ClientOAuth2Token;
}
