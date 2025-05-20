const assert = require('assert');
const client = require('../src/client');
const { calculatePedersenHash } = require('../src/common/helper');
const { Request } = require('../src/common/request');

describe('client API test', function () {
    it('generate key pair, sign data, and verify signature', async function () {
        const keys1 = await client.genKeyPair();
        const keys2 = await client.genKeyPair();
        console.log('Result:', keys1, keys2);

        const userAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
        const providerAddress = '0x1234567890123456789012345678901234567890';
        const userAddressBigInt = BigInt(userAddress);
        const providerAddressBigInt = BigInt(providerAddress);

        const requests = [
            new Request(
                '1',
                '5',
                userAddress,
                providerAddress,
                await calculatePedersenHash(BigInt('1'), userAddressBigInt, providerAddressBigInt),
                '2'
            ),
            new Request(
                '2',
                '6',
                userAddress,
                providerAddress,
                await calculatePedersenHash(BigInt('2'), userAddressBigInt, providerAddressBigInt),
                '3'
            ),
            new Request(
                '17325017303560040',
                '7',
                userAddress,
                providerAddress,
                await calculatePedersenHash(
                    BigInt('17325017303560040'),
                    userAddressBigInt,
                    providerAddressBigInt
                ),
                '4'
            ),
        ];
        console.log('requests:', requests);

        const signatures = await client.signData(
            requests,
            [keys1.packPrivkey0, keys1.packPrivkey1],
            [keys2.packPrivkey0, keys2.packPrivkey1]
        );
        console.log('signatures:', signatures);

        const isValid = await client.verifySignature(
            requests,
            signatures.reqSigs,
            [keys1.packedPubkey0, keys1.packedPubkey1],
            signatures.resSigs,
            [keys2.packedPubkey0, keys2.packedPubkey1]
        );
        console.log('isValid:', isValid);
        isValid.reqIsValid.forEach((element) => {
            assert.ok(element);
        });
        isValid.resIsValid.forEach((element) => {
            assert.ok(element);
        });
    });
});
