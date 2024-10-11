export function genKeyPair(): Promise<{
    packPrivkey0: bigint;
    packPrivkey1: bigint;
    packedPubkey0: bigint;
    packedPubkey1: bigint;
}>;
export function signData(data: any, privkey: any): Promise<any[]>;
export function verifySignature(data: any, signatures: any, pubkey: any): Promise<any[]>;
