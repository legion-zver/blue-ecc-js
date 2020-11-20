/**
 * Compatible with https://github.com/IBM-Swift/BlueECC
 * Compatible with kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM (iOS/Mac)
 */

export interface Keys {
    private: Buffer,
    public: Buffer,
    // noinspection SpellCheckingInspection
    pems: {
        public: string,
        private: string,
        publicBase64: string,
        privateBase64: string,
    }
}

/**
 * Generate keys
 */
export function generateKeys(): Keys;

/**
 * Get public key from private key
 */
export function getPublicKey(privateKey: Buffer | string): Buffer;

/**
 * Extract base64 key from pem/pemBase64 string
 */
export function extractKeyData(key: string, format?: string, isBase64?: boolean): string

/**
 * Decrypt data
 */
export function decrypt(privateKey: Buffer | string, data: Buffer | string): string

/**
 * Encrypt data
 */
export function encrypt(publicKey: Buffer | string, data: string): string

/**
 * Sign
 */
export function sign(privateKey: Buffer | string, data: Buffer | string): string;

/**
 * Verify
 */
export function verify(publicKey: Buffer | string, data: Buffer | string, signature: Buffer | string): boolean;
