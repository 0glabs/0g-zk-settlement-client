export function generateProofInput(requests: any, l: any, pubkey: any, signBuff: any): Promise<{
    serializedRequest: any;
    signer: any[];
    r8: any;
    s: any;
}>;
export function signAndVerifyRequests(requests: any, babyJubJubPrivateKey: any, babyJubJubPublicKey: any): Promise<{
    packPubkey: any;
    r8: any[];
    s: any[];
}>;
export function signRequests(requests: any, babyJubJubPrivateKey: any): Promise<any[]>;
export function verifySig(requests: any, signatures: any, pubkey: any): Promise<any[]>;
export function genPubkey(privkey: any): Promise<any>;
