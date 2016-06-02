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
    refreshToken: string;
    expires: Date;
    identityToken: string;
    _accessToken: string;
    accessToken: string;
    constructor(client: any, data: any);
    expiresIn(duration: any): Date;
    sign(requestObject: any): any;
    request(options: any): any;
    refresh(options?: any): any;
    expired: boolean;
}
export declare abstract class Flow {
    client: ClientOAuth2;
    constructor(client: any);
    getUserInfo(accessToken: string): UserInfoResponse;
}
export declare class TokenFlow extends Flow {
    getUri(options?: any): string;
    getToken(uri: any, state?: any, options?: any): ClientOAuth2Token;
}
export declare abstract class Claimable {
    getClaim(claimName: string): any;
}
export declare class UserInfoResponse extends Claimable {
    sub: string;
    constructor(sub: string);
}
