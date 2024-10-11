const eddsa = require('./crypto');
const utils = require('./utils');
const { Request } = require('./request');

async function generateProofInput(requests, l, pubkey, signBuff) {
    await eddsa.init();
    
    const r8 = [];
    const s = [];
    for (let i = 0; i < signBuff.length; i++) {
        r8.push(new Uint8Array(signBuff[i].slice(0, 32)));
        s.push(new Uint8Array(signBuff[i].slice(32, 64)));
    }

    const paddingResult = await paddingSignature(requests, r8, s, l);

    const input = {
        serializedRequest: paddingResult.serializedRequestTrace,
        signer: [pubkey[0].toString(16), pubkey[1].toString(16)],
        r8: paddingResult.r8,
        s: paddingResult.s
    };

    return input;
}

// 辅助函数：签名并验证请求
async function signAndVerifyRequests(requests, babyJubJubPrivateKey, babyJubJubPublicKey) {
    await eddsa.init();

    const packPubkey = eddsa.packPoint(babyJubJubPublicKey);
    const signatures = [];
    const r8 = [];
    const s = [];
    const serializedRequestTrace = requests.map(request => request.serialize());

    for (let i = 0; i < serializedRequestTrace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(serializedRequestTrace[i], babyJubJubPrivateKey);
        signatures.push(signature);

        const isValid = await eddsa.babyJubJubVerify(serializedRequestTrace[i], signature, babyJubJubPublicKey);
        console.log("Signature", i, "is valid:", isValid);

        const packedSig = eddsa.packSignature(signature);
        r8.push(packedSig.slice(0, 32));
        s.push(packedSig.slice(32, 64));
    }
    return { packPubkey, r8, s };
}

async function signRequests(requests, babyJubJubPrivateKey) {
    await eddsa.init();

    const serializedRequestTrace = requests.map(request => request.serialize());
    const signatures = [];
    for (let i = 0; i < serializedRequestTrace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(serializedRequestTrace[i], babyJubJubPrivateKey);
        signatures.push(eddsa.packSignature(signature));
    }
    return signatures;
}

async function verifySig(requests, signatures, pubkey) {
    await eddsa.init();

    const unpackPubkey = new Uint8Array(32);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[0]), 16), 0);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[1]), 16), 16);
    const babyJubJubPublicKey = eddsa.unpackPoint(unpackPubkey);

    const isValid = [];
    const serializedRequestTrace = requests.map(request => request.serialize());

    for (let i = 0; i < serializedRequestTrace.length; i++) {
        const unpackSignature = eddsa.unpackSignature(new Uint8Array(signatures[i]));
        isValid.push(await eddsa.babyJubJubVerify(serializedRequestTrace[i], unpackSignature, babyJubJubPublicKey));
    }
    return isValid;
}

// 辅助函数：填充签名
function paddingSignature(requests, r8, s, l) {
    if (l < requests.length) {
        throw new Error('l must be greater than or equal to the length of serializedRequestTrace');
    }

    const lastRequest = requests[requests.length - 1];
    const lastR8 = r8[r8.length - 1];
    const lastS = s[s.length - 1];

    let currentNonce = lastRequest.nonce;
    for (let i = requests.length; i < l; i++) {
        currentNonce += 1;
        const noopRequest = new Request(
            currentNonce,
            0,
            '0x' + lastRequest.userAddress.toString(16),
            '0x' + lastRequest.providerAddress.toString(16)
        );

        requests.push(noopRequest);
        r8.push(lastR8);
        s.push(lastS);
    }

    const serializedRequestTrace = requests.map(request => request.serialize());
    return { serializedRequestTrace, r8, s };
}

async function genPubkey(privkey) {
    await eddsa.init();

    return eddsa.babyJubJubGeneratePublicKey(privkey);
}

module.exports = {
    generateProofInput,
    signAndVerifyRequests,
    signRequests,
    verifySig,
    genPubkey
};