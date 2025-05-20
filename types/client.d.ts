export function genKeyPair(): Promise<{
    packPrivkey0: bigint;
    packPrivkey1: bigint;
    packedPubkey0: bigint;
    packedPubkey1: bigint;
}>;
export function signData(data: any, reqPrivkey: any, resPrivkey: any): Promise<{
    reqSigs: any[];
    resSigs: any[];
}>;
export function verifySignature(data: any, reqSig: any, reqPubkey: any, resSig: any, resPubkey: any): Promise<{
    reqIsValid: any[];
    resIsValid: any[];
}>;
