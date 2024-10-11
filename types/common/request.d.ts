export class Request {
    static deserialize(byteArray: any): Request;
    constructor(nonce: any, fee: any, userAddress: any, providerAddress: any);
    nonce: number;
    fee: bigint;
    userAddress: bigint;
    providerAddress: bigint;
    serialize(): Uint8Array;
}
