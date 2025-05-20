const crypto = require('./common/crypto');
const utils = require('./common/utils');
const helper = require('./common/helper');

async function genKeyPair() {
    await crypto.init();

    const privkey = crypto.babyJubJubGeneratePrivateKey();
    const pubkey = crypto.babyJubJubGeneratePublicKey(privkey);

    const packedPubkey = crypto.packPoint(pubkey);
    const packedPubkey0 = utils.bytesToBigint(packedPubkey.slice(0, 16));
    const packedPubkey1 = utils.bytesToBigint(packedPubkey.slice(16));
    const packPrivkey0 = utils.bytesToBigint(privkey.slice(0, 16));
    const packPrivkey1 = utils.bytesToBigint(privkey.slice(16));
    return { packPrivkey0, packPrivkey1, packedPubkey0, packedPubkey1 };
}

async function genCombinedKey(privkey0, privkey1) {
    const packedPrivkey0 = utils.bigintToBytes(privkey0, 16);
    const packedPrivkey1 = utils.bigintToBytes(privkey1, 16);
    const combinedKey = new Uint8Array(32);
    combinedKey.set(packedPrivkey0, 0);
    combinedKey.set(packedPrivkey1, 16);
    return combinedKey;
}

async function signData(data, reqPrivkey, resPrivkey) {
    const reqKey = await genCombinedKey(reqPrivkey[0], reqPrivkey[1]);
    const resKey = await genCombinedKey(resPrivkey[0], resPrivkey[1]);

    return await helper.signRequests(data, reqKey, resKey);
}

async function verifySignature(data, reqSig, reqPubkey, resSig, resPubkey) {
    return await helper.verifySig(data, reqSig, reqPubkey, resSig, resPubkey);
}

module.exports = {
    genKeyPair,
    signData,
    verifySignature,
};
