/**
 * Compatible with https://github.com/IBM-Swift/BlueECC
 * Compatible with kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM (iOS/Mac)
 */

"use strict";

import {getPublicKey} from "./index";

const crypto = require("crypto");
const ECKey = require("ec-key");

const curve = "prime256v1";
const algorithm = "aes-128-gcm";
const signAlgorithm = "RSA-SHA256";

/**
 * Generate keys
 *
 * @returns {{private: Buffer, public: Buffer, pemBase64: {private: string, public: string}}}
 */
module.exports.generateKeys = function() {
	// noinspection JSUnresolvedFunction,JSUnresolvedVariable
	const key = ECKey.createECKey(curve),
		privatePem = key.toString("rfc5915"),
		publicPem = key.asPublicECKey().toString("pem");
	// noinspection JSValidateTypes,SpellCheckingInspection,JSUnresolvedVariable
	return {
		pems: {
			public: publicPem,
			private: privatePem,
			publicBase64: Buffer.from(publicPem, 'utf8').toString('base64'),
			privateBase64: Buffer.from(privatePem, 'utf8').toString('base64'),
		},
		public: key.publicCodePoint,
		private: key.d,
	};
}

/**
 * @param privateKey - string in base64 or Buffer
 *
 * @return {Buffer}
 */
module.exports.getPublicKey = function (privateKey) {
	return crypto.createECDH(curve).setPrivateKey(
		typeof privateKey === 'string' ? Buffer.from(privateKey, 'base64') : privateKey
	).getPublicKey();
}

/**
 * Extract base64 key from pem/pemBase64 string
 *
 * @param {string} key
 * @param {string} format
 * @param {boolean} isBase64
 *
 * @return {string}
 */
module.exports.extractKeyData = function(key, format = "pem", isBase64 = false) {
	if (isBase64) {
		key = Buffer.from(key, 'base64').toString();
	}
	const ecKey = new ECKey(key, format)
	if (ecKey.isPrivateECKey) {
		return ecKey.d.toString('base64');
	}
	return ecKey.publicCodePoint.toString('base64');
}

/**
 * Decrypt data
 *
 * @param privateKey - string in base64 or Buffer
 * @param data - string in base64
 *
 * @returns {string}
 */
module.exports.decrypt = function (privateKey, data) {
	privateKey = typeof privateKey === 'string' ? Buffer.from(privateKey, 'base64') : privateKey;
	const ecKey = new ECKey({
		publicKey: getPublicKey(privateKey),
		privateKey,
		curve,
	});
	const ecdh = ecKey.createECDH(),
		encrypted = typeof data === 'string' ? Buffer.from(data, 'base64') : data

	// INFO parts data from data
	// noinspection SpellCheckingInspection
	const ephemeralPublicKey = encrypted.slice(0, 65),
		symKey = ecdh.computeSecret(ephemeralPublicKey),
		ciphertext = encrypted.slice(65, -16),
		preHashKey = Buffer.concat([
			symKey,
			Buffer.from([0x00, 0x00, 0x00, 0x01]),
			ephemeralPublicKey,
		]),
		tag = encrypted.slice(-16);

	// INFO: Use SHA256 ANSI x9.63 Key Derivation Function with the ephemeral public key to generate a 32 byte key
	const hashedKey = crypto.createHash("sha256").update(preHashKey).digest();

	// INFO: Use the second 16 bytes as the initialization vector (IV)
	const aesKey = hashedKey.slice(0, 16);

	// INFO: Use the second 16 bytes as the initialization vector (IV)
	const iv = hashedKey.slice(-16);

	// INFO: Use aes_128_gcm to decrypt
	const cipher = crypto.createDecipheriv(algorithm, aesKey, iv, {authTagLength: 16});
	cipher.setAuthTag(tag);

	return Buffer.concat([cipher.update(ciphertext), cipher.final()]).toString();
}

/**
 * Encrypt data
 *
 * @param publicKey - string in base64 or Buffer
 * @param {string} data - string in utf8
 *
 * @returns {string} base64
 */
module.exports.encrypt = function (publicKey, data) {
	const ephemeralKey = ECKey.createECKey(curve);
	const ecdh = ephemeralKey.createECDH();

	// INFO: Generate an ephemeral EC key pair
	const ephemeralPublicKey = ecdh.getPublicKey();

	// INFO: Use ECDH of your EC pair to generate a symmetric key
	const symKey = ecdh.computeSecret(typeof publicKey === 'string' ? Buffer.from(publicKey, 'base64') : publicKey);

	// INFO: Use SHA256 ANSI x9.63 Key Derivation Function with the ephemeral public key to generate a 32 byte key
	const preHashKey = Buffer.concat([
		symKey,
		Buffer.from([0x00, 0x00, 0x00, 0x01]),
		ephemeralPublicKey,
	])
	const hashedKey = crypto.createHash("sha256").update(preHashKey).digest();

	// INFO: Use the second 16 bytes as the initialization vector (IV)
	const aesKey = hashedKey.slice(0, 16);

	// INFO: Use the second 16 bytes as the initialization vector (IV)
	const iv = hashedKey.slice(-16);

	// INFO: Use aes_128_gcm to encrypt the plaintext and generate a 16 byte GCM tag
	// noinspection SpellCheckingInspection
	const cipher = crypto.createCipheriv(algorithm, aesKey, iv),
		firstChunk = cipher.update(Buffer.from(data, "utf8")),
		secondChunk = cipher.final(),
		tag = cipher.getAuthTag(),
		ciphertext = Buffer.concat([firstChunk, secondChunk]);

	return Buffer.concat([ephemeralPublicKey, ciphertext, tag]).toString('base64');
}

module.exports.sign = function (privateKey, data) {
	const ecdh = crypto.createECDH(curve);
	ecdh.setPrivateKey(typeof privateKey === 'string' ? Buffer.from(privateKey, 'base64') : privateKey);
	const key = new ECKey({
		privateKey: ecdh.getPrivateKey(),
		publicKey: ecdh.getPublicKey(),
		curve: curve
	});
	const signer = crypto.createSign(signAlgorithm)
	signer.update(typeof data === 'string' ? Buffer.from(data, "utf8") : data)
	return signer.sign(key.toString("rfc5915"), 'base64')
}

module.exports.verify = function (publicKey, data, signature) {
	const key = new ECKey({
		publicKey: typeof publicKey === 'string' ? Buffer.from(publicKey, 'base64') : publicKey,
		curve: curve
	});
	const verifier = crypto.createVerify(signAlgorithm);
	verifier.update(typeof data === 'string' ? Buffer.from(data, "utf8") : data);
	return verifier.verify(
		key.asPublicECKey().toString('pem'),
		typeof signature === 'string' ? Buffer.from(signature, 'base64') : signature,
	)
}
