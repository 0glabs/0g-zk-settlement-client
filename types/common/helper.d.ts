export function calculatePedersenHash(nonce: any, userAddress: any, providerAddress: any): Promise<any>;
export function generateProofInput(requests: any, l: any, reqPubkey: any, reqSignBuff: any, resPubkey: any, resSignBuff: any, tree: any): Promise<{
    input: {
        serializedInput: any;
        reqSigner: any[];
        resSigner: any[];
        reqR8: any;
        reqS: any;
        resR8: any;
        resS: any;
        pathElements: any[][];
        pathIndices: any[][];
        roots: any[];
        leaf: any;
    };
    leaves: any[];
}>;
export function signAndVerifyRequests(requests: any, babyJubJubPrivateKey: any, babyJubJubPublicKey: any, isRequest: any): Promise<{
    packPubkey: any;
    r8: any[];
    s: any[];
}>;
export function signRequests(requests: any, privKey: any, signResponse: any): Promise<any[]>;
export function verifySig(requests: any, sig: any, pubKey: any, signResponse: any): Promise<any[]>;
export function genPubkey(privkey: any): Promise<any>;
/**
 * Generate merkle tree for a deposit.
 * Download deposit events from the contract, reconstructs merkle tree, finds our deposit leaf
 * in it and generates merkle proof
 */
export function generateMerkleProofBatch(nonces: any, tree: any, l: any): Promise<{
    leaves: any[];
    pathElements: any[][];
    pathIndices: any[][];
}>;
export function calculateNonceHash(nonce: any): Promise<any>;
export function firstBytesToIndex(u8arr: any, cap: any): number;
export function toHex(input: any): string;
