const crypto = require('./common/crypto');
const utils = require('./common/utils');
const helper = require('./common/helper')

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

async function signData(data, privkey) {
    const privkey0 = utils.bigintToBytes(privkey[0], 16)
    const privkey1 = utils.bigintToBytes(privkey[1], 16)
    const combinedKey = new Uint8Array(32);
    combinedKey.set(privkey0, 0); 
    combinedKey.set(privkey1, 16);

    const signatures = await helper.signRequests(data, combinedKey);
    return signatures;
}

async function verifySignature(data, signatures, pubkey) {
    const isValid = await helper.verifySig(data, signatures, pubkey)
    return isValid;
}

module.exports = {
    genKeyPair,
    signData,
    verifySignature
}