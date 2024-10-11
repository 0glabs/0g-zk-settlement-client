const assert = require('assert');
const client = require('../src/client')
const { Request } = require('../src/common/request');

describe('client API test', function () {
  it('generate key pair, sign data, and verify signature', async function () {
    const keys = await client.genKeyPair();
    console.log("Result:", keys);

    const userAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
    const providerAddress = '0x1234567890123456789012345678901234567890';

    const requests = [
        new Request('1', '5', userAddress, providerAddress),
        new Request('2', '6', userAddress, providerAddress),
        new Request('3', '7', userAddress, providerAddress)
    ];
    console.log("requests:", requests);

    const signatures = await client.signData(requests, [keys.packPrivkey0, keys.packPrivkey1])
    console.log("signatures:", signatures);

    const isValid = await client.verifySignature(requests, signatures, [keys.packedPubkey0, keys.packedPubkey1])
    console.log("isValid:", isValid);
    isValid.forEach((element) => {
      assert.ok(element);
    });
  });
});

