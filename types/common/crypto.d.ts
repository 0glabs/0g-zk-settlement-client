export function init(): Promise<void>;
export function babyJubJubGeneratePrivateKey(): any;
export function babyJubJubGeneratePublicKey(privateKey: any): any;
export function babyJubJubSignature(msg: any, privateKey: any): Promise<any>;
export function babyJubJubVerify(msg: any, signature: any, publicKey: any): Promise<any>;
export function packSignature(signature: any): any;
export function packPoint(point: any): any;
export function hash(msg: any): any;
export function unpackSignature(signBuff: any): any;
export function unpackPoint(point: any): any;
