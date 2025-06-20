const assert = require('assert');
const client = require('../src/client');
const { calculatePedersenHash, toHex } = require('../src/common/helper');
const { Request } = require('../src/common/request');
const circomlibjs = require('circomlibjs');

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

        const reqSigs = await client.signData(
            requests,
            [keys1.packPrivkey0, keys1.packPrivkey1],
            false
        );
        console.log('signatures:', reqSigs);

        const resSigs = await client.signData(
            requests,
            [keys2.packPrivkey0, keys2.packPrivkey1],
            true
        );
        console.log('signatures:', resSigs);

        let isValid = await client.verifySignature(
            requests,
            reqSigs,
            [keys1.packedPubkey0, keys1.packedPubkey1],
            false
        );
        console.log('isValid:', isValid);
        isValid.forEach((element) => {
            assert.ok(element);
        });

        isValid = await client.verifySignature(
            requests,
            resSigs,
            [keys2.packedPubkey0, keys2.packedPubkey1],
            true
        );
        console.log('isValid:', isValid);
        isValid.forEach((element) => {
            assert.ok(element);
        });
    });

    it('verify root calculation', async function () {
        let leafHex = '099aa18ca834a14066f6ca5a556c1339426e692e';
        let pathElements = [
            '00000000000000000000',
            '20636625426020718969131298365984859231982649550971729229988535915544421356929',
            '8234632431858659206959486870703726442454087730228411315786216865106603625166',
            '7985001422402102077350925203503698316627789269711557462970266825665867053007',
            '18097266179879782427361438755277450939722755112152115227098348943187633376449',
        ];
        let pathIndices = [0, 0, 0, 1, 0];
        let expectedRootDec = '16425746924271915316353948346176207381088023153859176687170480149167476312548';

        // 2) Build the MiMC sponge
        const mimc = await circomlibjs.buildMimcSponge();

        // 3) Parse inputs into BigInt
        let cur = BigInt('0x' + leafHex);
        const root = BigInt(expectedRootDec);

        // 4) Walk up the tree
        for (let i = 0; i < pathElements.length; i++) {
            const sibling = BigInt(pathElements[i]);
            let left, right;
            if (pathIndices[i] === 0) {
                left = cur;
                right = sibling;
            } else {
                left = sibling;
                right = cur;
            }
            console.log(`Step ${i + 1}: left=${left}, right=${right}, sibling=${sibling}`);
            // MiMCSponge(2,1) with key=0 is just mimc.hash(left, right)
            let curBytes = mimc.multiHash([left, right]);
            cur = mimc.F.toString(curBytes, 10);
        }

        assert.strictEqual(cur.toString(), root.toString(), 'Root calculation mismatch');
    });
});
