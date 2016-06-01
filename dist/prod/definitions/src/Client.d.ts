export interface RequestOptions {
    body: any;
    query: any;
    headers: any;
    options: any;
    method: string;
    url: string;
}
export declare class ClientOAuth2 {
    token: TokenFlow;
    options: any;
    constructor(options: any);
    createToken(access: string, refresh: string, type: string, data: any): ClientOAuth2Token;
    _request(requestObject: RequestOptions): any;
}
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
export declare class TokenFlow {
    client: ClientOAuth2;
    constructor(client: any);
    getUri(options?: any): string;
    getToken(uri: any, state?: any, options?: any): ClientOAuth2Token;
}
