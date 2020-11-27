"use strict";

const ecc = require('../index');

const privateKey = Buffer.from(ecc.extractKeyData('-----BEGIN EC PRIVATE KEY-----\n' +
'MHcCAQEEIF8eZuR4JQpE4gwurA+egKK/F25AH02nNw7SBbaObYZFoAoGCCqGSM49\n' +
'AwEHoUQDQgAEpPF/CPJvvBIbu2e1zNKMpBjjnySwFFhASaQsJsMrXi2taSIHNbkE\n' +
'3laA1UaP8Gdl5yrFxVLHs33h4hsHH0SqZg==\n' +
'-----END EC PRIVATE KEY-----'), 'base64');

const publicKey = Buffer.from(ecc.extractKeyData('-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpPF/CPJvvBIbu2e1zNKMpBjjnySw\n' +
'FFhASaQsJsMrXi2taSIHNbkE3laA1UaP8Gdl5yrFxVLHs33h4hsHH0SqZg==\n' +
'-----END PUBLIC KEY-----'), 'base64');

const publicClientKey = Buffer.from(ecc.extractKeyData('-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+LbPrJ2Iw2i/bAkNWi2kJi0JpLq\n' +
'AM2oJznUfqzx4CDErLXPCOBuXLUanduUjquidtL4MtGxGZjO73gCkXRW0Q==\n' +
'-----END PUBLIC KEY-----'), 'base64');

const enc = ecc.encrypt(publicClientKey, "hello world");
console.log('enc:', enc);

const dec = ecc.decrypt(privateKey, "BDAVhzTbf2XVlPFPcZEtpubR1Vbt8T/LxS2W4vCeQ+CoiT070t0AcGK2e7s7Wisw1rOBgXhLNhR6IM+xY61XVPSrKNgxHLAzVFTJwvOw1isOJ1ooodf7pw==");
console.log('dec:', dec);

const sign = ecc.sign(privateKey, "hello world")
console.log('\nsign (hello world):', sign);

console.log('verify (hello world):', ecc.verify(publicKey, "hello world", sign));

/*
enc: BFCcmlGDU+I35+94Cj9w8wXyGb6AAM6Y1+QYgvo+yac0O2Y+OS2Fu2q6GI/7UUX4wXcgJHWSlEizNuCWvaXZBdsxGo13aIcNHm0X8008muCO9OpKs4z1+j4uQkg=
dec: welcome
 */

console.log('\nnext private key:', ecc.generateKeys().private.toString('base64'));
