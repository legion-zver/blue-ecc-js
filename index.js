/**
 * Compatible with https://github.com/IBM-Swift/BlueECC
 * Compatible with kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM (iOS/Mac)
 */

"use strict";

const crypto = require("crypto");
const ECKey = require("ec-key");

const curve = "prime256v1";
const algorithm = "aes-128-gcm";

/**
 * Generate keys
 *
 * @returns {{private: Buffer, public: Buffer, pemBase64: {private: string, public: string}}}
 */
module.exports.generateKeys = function() {
	// noinspection JSUnresolvedFunction,JSUnresolvedVariable
	const key = ECKey.createECKey(curve),
		privatePem = key.toBuffer("pem"),
		publicPem = new ECKey({
			publicKey: key.publicCodePoint,
			curve: curve,
		}).toBuffer("pem");
	// noinspection JSValidateTypes,SpellCheckingInspection,JSUnresolvedVariable
	return {
		pems: {
			public: publicPem.toString(),
			private: privatePem.toString(),
			publicBase64: publicPem.toString('base64'),
			privateBase64: privatePem.toString('base64'),
		},
		public: key.publicCodePoint,
		private: key.d,
	};
}

/**
 * Extract base64 key from pem/pemBase64 string
 *
 * @param {string} key
 * @param {string} format
 * @param {boolean} isBase64
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
 * ECC Decrypt data
 *
 * @param {string | Buffer} privateKey - string in base64
 * @param {string | Buffer} publicKey - string in base64
 * @param {string | Buffer} data - string in base64
 *
 * @returns {string} base64
 */
module.exports.decrypt = function (privateKey, publicKey, data) {
	const ecKey = new ECKey({
		privateKey: typeof privateKey === 'string' ? Buffer.from(privateKey, 'base64') : privateKey,
		publicKey: typeof publicKey === 'string' ? Buffer.from(publicKey, 'base64') : publicKey,
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
 * ECC Encrypt data
 *
 * @param {string | Buffer} privateKey - string in base64
 * @param {string | Buffer} publicKey - string in base64
 * @param {string} data - string in utf8
 *
 * @returns {string} base64
 */
module.exports.encrypt = function (privateKey, publicKey, data) {
	const ecKey = new ECKey({
		privateKey: typeof privateKey === 'string' ? Buffer.from(privateKey, 'base64') : privateKey,
		publicKey: typeof publicKey === 'string' ? Buffer.from(publicKey, 'base64') : publicKey,
		curve,
	});
	const ecdh = ecKey.createECDH();
	
	// INFO: Generate an ephemeral EC key pair
	const ephemeralPublicKey = ECKey.createECKey(curve).createECDH().getPublicKey();
	
	// INFO: Use ECDH of your EC pair to generate a symmetric key
	const symKey = ecdh.computeSecret(ephemeralPublicKey);
	
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
