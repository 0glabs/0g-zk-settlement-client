const utils = require('./utils');

const ADDR_LENGTH = 20;
const NONCE_LENGTH = 8;
const FEE_LENGTH = 16;  // u128 的长度为 16 字节

class Request {
    constructor(nonce, fee, userAddress, providerAddress) {
        this.nonce = BigInt(nonce);
        this.fee = BigInt(fee);

        // userAddress 和 providerAddress 为 u160 以 hexstring 形式输入
        this.userAddress = BigInt(userAddress);
        this.providerAddress = BigInt(providerAddress);
    }

    serialize() {
        const buffer = new ArrayBuffer(NONCE_LENGTH + ADDR_LENGTH * 2 + FEE_LENGTH);
        let offset = 0;

        // 写入 nonce (u64)
        const nonceBytes = utils.bigintToBytes(this.nonce, NONCE_LENGTH);
        console.log('nonceBytes:', nonceBytes, 'nonce:', this.nonce);
        new Uint8Array(buffer, offset, NONCE_LENGTH).set(nonceBytes);
        offset += NONCE_LENGTH;

        // 写入 fee (u128)
        const feeBytes = utils.bigintToBytes(this.fee, FEE_LENGTH);
        new Uint8Array(buffer, offset, FEE_LENGTH).set(feeBytes);
        offset += FEE_LENGTH;

        // 写入 userAddress (u160)
        const userAddressBytes = utils.bigintToBytes(this.userAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(userAddressBytes);
        offset += ADDR_LENGTH;

        // 写入 providerAddress (u160)
        const providerAddressBytes = utils.bigintToBytes(this.providerAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(providerAddressBytes);
        offset += ADDR_LENGTH;

        return new Uint8Array(buffer);
    }

    static deserialize(byteArray) {
        const expectedLength = NONCE_LENGTH + ADDR_LENGTH * 2 + FEE_LENGTH;

        if (byteArray.length !== expectedLength) {
            throw new Error(`Invalid byte array length for deserialization. Expected: ${expectedLength}, but got: ${byteArray.length}`);
        }

        const view = new DataView(byteArray.buffer);
        let offset = 0;

        // 读取 nonce (u64)
        const nonce = utils.bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + NONCE_LENGTH)));
        offset += NONCE_LENGTH;

        // 读取 fee (u128)
        const fee = utils.bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + FEE_LENGTH)));
        offset += FEE_LENGTH;

        // 读取 userAddress (u160)
        const userAddress = utils.bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH)));
        offset += ADDR_LENGTH;

        // 读取 providerAddress (u160)
        const providerAddress = utils.bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH)));
        offset += ADDR_LENGTH;
        
        return new Request(
            nonce.toString(),
            fee.toString(),
            '0x' + userAddress.toString(16),
            '0x' + providerAddress.toString(16)
        );
    }
}

module.exports = { Request };
