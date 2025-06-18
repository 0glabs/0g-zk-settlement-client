const eddsa = require('./crypto');
const utils = require('./utils');
const { Request, NONCE_LENGTH, ADDR_LENGTH } = require('./request');

function firstBytesToIndex(u8arr, cap) {
    // take bytes 0–19
    const slice = u8arr.slice(0, cap);
    // convert to a hex string
    const hex = Buffer.from(slice).toString('hex');
    // parse as BigInt
    const val = BigInt('0x' + hex);
    return Number(val % BigInt(2 ** cap));
}

function toHex(input) {
    let hex;
    if (Array.isArray(input) || input instanceof Uint8Array) {
        hex = Buffer.from(input).toString('hex');
    } else {
        hex = BigInt(input).toString(16);
    }

    // 2) pad to the right byte length and prefix “0x”
    return '0x' + hex.padStart(utils.LEAF_SIZE, '0');
}

/**
 * Generate merkle tree for a deposit.
 * Download deposit events from the contract, reconstructs merkle tree, finds our deposit leaf
 * in it and generates merkle proof
 */
async function generateMerkleProofBatch(nonces, tree, l) {
    await eddsa.init();

    const batchSize = nonces.length;

    // Initialise 2-D arrays
    const pathElements = Array.from({ length: batchSize }, () => Array(tree.levels));
    const pathIndices = Array.from({ length: batchSize }, () => Array(tree.levels));
    const leaves = [];

    for (let i = 0; i < batchSize; i++) {
        const nonce = nonces[i];

        const leaf = await calculateNonceHash(BigInt(nonce));
        
        const leafIndex = firstBytesToIndex(leaf, tree.levels);

        const leafHex = toHex(leaf);
        
        leaves[i] = leaf;
        tree.update(leafIndex, leafHex);
        const proofPath = tree.path(leafIndex);

        if (proofPath.pathElements.length !== tree.levels) {
            throw new Error(
                `wrong depth: wanted ${tree.levels}, got ${proofPath.pathElements.length}`
            );
        }

        pathElements[i] = proofPath.pathElements; // stores the *entire* sibling list → list-of-lists
        pathIndices[i] = proofPath.pathIndices; // stores the 0/1 flags         → list-of-lists
    }

    for (let i = batchSize; i < l; i++) {
        pathElements.push(pathElements[batchSize - 1]);
        pathIndices.push(pathIndices[batchSize - 1]);
    }

    return { leaves, pathElements, pathIndices };
}

async function calculatePedersenHash(nonce, userAddress, providerAddress) {
    await eddsa.init();

    const buffer = new ArrayBuffer(NONCE_LENGTH + ADDR_LENGTH * 2);
    let offset = 0;

    // 写入 nonce (u64)
    const nonceBytes = utils.bigintToBytes(nonce, NONCE_LENGTH);
    new Uint8Array(buffer, offset, NONCE_LENGTH).set(nonceBytes);
    offset += NONCE_LENGTH;

    // 写入 userAddress (u160)
    const userAddressBytes = utils.bigintToBytes(userAddress, ADDR_LENGTH);
    new Uint8Array(buffer, offset, ADDR_LENGTH).set(userAddressBytes);
    offset += ADDR_LENGTH;

    // 写入 providerAddress (u160)
    const providerAddressBytes = utils.bigintToBytes(providerAddress, ADDR_LENGTH);
    new Uint8Array(buffer, offset, ADDR_LENGTH).set(providerAddressBytes);

    const hash = eddsa.hash(Buffer.from(buffer));

    return hash;
}

async function calculateNonceHash(nonce) {
    await eddsa.init();
    const buffer = new ArrayBuffer(NONCE_LENGTH);

    const nonceBytes = utils.bigintToBytes(nonce, NONCE_LENGTH);
    new Uint8Array(buffer, 0, NONCE_LENGTH).set(nonceBytes);
    const hash = eddsa.hash(Buffer.from(buffer));
    return hash.slice(0, utils.LEAF_SIZE);
}

async function generateProofInput(
    requests,
    l,
    reqPubkey,
    reqSignBuff,
    resPubkey,
    resSignBuff,
    tree
) {
    await eddsa.init();

    const reqR8 = [];
    const reqS = [];
    for (let i = 0; i < reqSignBuff.length; i++) {
        reqR8.push(new Uint8Array(reqSignBuff[i].slice(0, 32)));
        reqS.push(new Uint8Array(reqSignBuff[i].slice(32, 64)));
    }

    const resR8 = [];
    const resS = [];
    for (let i = 0; i < resSignBuff.length; i++) {
        resR8.push(new Uint8Array(resSignBuff[i].slice(0, 32)));
        resS.push(new Uint8Array(resSignBuff[i].slice(32, 64)));
    }

    const oldRoot = tree.root;
    const nonces = requests.map((request) => request.nonce);
    const { leaves, pathElements, pathIndices } = await generateMerkleProofBatch(nonces, tree, l);

    const paddingResult = await paddingSignature(requests, reqR8, reqS, resR8, resS, l);

    const input = {
        serializedInput: paddingResult.serializedInputTrace,
        reqSigner: [reqPubkey[0].toString(16), reqPubkey[1].toString(16)],
        resSigner: [resPubkey[0].toString(16), resPubkey[1].toString(16)],
        reqR8: paddingResult.reqR8,
        reqS: paddingResult.reqS,
        resR8: paddingResult.resR8,
        resS: paddingResult.resS,
        pathElements: pathElements,
        pathIndices: pathIndices,
        roots: [oldRoot, tree.root],
    };

    return { input, leaves };
}

// 辅助函数：签名并验证请求
async function signAndVerifyRequests(
    requests,
    babyJubJubPrivateKey,
    babyJubJubPublicKey,
    isRequest
) {
    await eddsa.init();

    const packPubkey = eddsa.packPoint(babyJubJubPublicKey);
    const signatures = [];
    const r8 = [];
    const s = [];

    var serializedInputTrace = [];
    if (isRequest) {
        serializedInputTrace = requests.map((request) => request.serializeRequest());
    } else {
        serializedInputTrace = requests.map((request) => request.serializeResponse());
    }

    for (let i = 0; i < serializedInputTrace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(
            serializedInputTrace[i],
            babyJubJubPrivateKey
        );
        signatures.push(signature);

        const isValid = await eddsa.babyJubJubVerify(
            serializedInputTrace[i],
            signature,
            babyJubJubPublicKey
        );

        const packedSig = eddsa.packSignature(signature);
        r8.push(packedSig.slice(0, 32));
        s.push(packedSig.slice(32, 64));
    }
    return { packPubkey, r8, s };
}

async function signRequestHelper(trace, privkey) {
    const sigs = [];
    for (let i = 0; i < trace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(trace[i], privkey);
        sigs.push(eddsa.packSignature(signature));
    }
    return sigs;
}

async function signRequests(requests, privKey, signResponse) {
    await eddsa.init();

    var trace;
    if (signResponse) {
        trace = requests.map((request) => request.serializeResponse());
    } else {
        trace = requests.map((request) => request.serializeRequest());
    }

    return await signRequestHelper(trace, privKey);
}

async function verifySigHelper(trace, sigs, pubkey) {
    const unpackPubkey = new Uint8Array(32);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[0]), 16), 0);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[1]), 16), 16);
    const unpackedPubkey = eddsa.unpackPoint(unpackPubkey);

    const isValid = [];
    for (let i = 0; i < trace.length; i++) {
        const unpackSignature = eddsa.unpackSignature(new Uint8Array(sigs[i]));
        isValid.push(await eddsa.babyJubJubVerify(trace[i], unpackSignature, unpackedPubkey));
    }
    return isValid;
}

async function verifySig(requests, sig, pubKey, signResponse) {
    await eddsa.init();

    var trace;
    if (signResponse) {
        trace = requests.map((request) => request.serializeResponse());
    } else {
        trace = requests.map((request) => request.serializeRequest());
    }

    return await verifySigHelper(trace, sig, pubKey);
}

// 辅助函数：填充签名
async function paddingSignature(requests, reqR8, reqS, resR8, resS, l) {
    if (l < requests.length) {
        throw new Error('l must be greater than or equal to the length of serializedInputTrace');
    }

    const lastRequest = requests[requests.length - 1];
    const lastReqR8 = reqR8[reqR8.length - 1];
    const lastReqS = reqS[reqS.length - 1];

    const lastResR8 = resR8[resR8.length - 1];
    const lastResS = resS[resS.length - 1];

    for (let i = requests.length; i < l; i++) {
        const noopRequest = new Request(
            lastRequest.nonce,
            0,
            '0x' + lastRequest.userAddress.toString(16),
            '0x' + lastRequest.providerAddress.toString(16),
            await calculatePedersenHash(
                lastRequest.nonce,
                lastRequest.userAddress,
                lastRequest.providerAddress
            ),
            0
        );

        requests.push(noopRequest);
        reqR8.push(lastReqR8);
        reqS.push(lastReqS);

        resR8.push(lastResR8);
        resS.push(lastResS);
    }

    const serializedInputTrace = requests.map((request) => request.serialize());
    return { serializedInputTrace, reqR8, reqS, resR8, resS };
}

async function genPubkey(privkey) {
    await eddsa.init();

    return eddsa.babyJubJubGeneratePublicKey(privkey);
}

module.exports = {
    calculatePedersenHash,
    generateProofInput,
    signAndVerifyRequests,
    signRequests,
    verifySig,
    genPubkey,
    generateMerkleProofBatch,
    calculateNonceHash,
    firstBytesToIndex,
    toHex,
};
