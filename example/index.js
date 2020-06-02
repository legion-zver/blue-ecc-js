/**
 * Example
 */

"use strict";

const ecc = require('../index');

const keys = ecc.generateKeys();
console.log('keys:', keys);
// -> keys: {
// 	pems: {
// 		public: '-----BEGIN PUBLIC KEY-----\n' +
// 		'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyInIDoJK1uW9/v9g9kvYmKoL2Z8\n' +
// 		'2Sp9dzF6NSN/jtzWJDi6MOYfGorwMfmSf75F1QgqRGLsOTYf+hmCks3DXw==\n' +
// 		'-----END PUBLIC KEY-----\n',
// 		private: '-----BEGIN PRIVATE KEY-----\n' +
// 		'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/GkXquaeZBH2iQxw\n' +
// 		'CBC9O3qwlaCc79FNGRxXzDOzzQKhRANCAASHIicgOgkrW5b3+/2D2S9iYqgvZnzZ\n' +
// 		'Kn13MXo1I3+O3NYkOLow5h8aivAx+ZJ/vkXVCCpEYuw5Nh/6GYKSzcNf\n' +
// 		'-----END PRIVATE KEY-----\n',
// 		publicBase64: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFaHlJbklEb0pLMXVXOS92OWc5a3ZZbUtvTDJaOAoyU3A5ZHpGNk5TTi9qdHpXSkRpNk1PWWZHb3J3TWZtU2Y3NUYxUWdxUkdMc09UWWYraG1Da3MzRFh3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
// 		privateBase64: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZy9Ha1hxdWFlWkJIMmlReHcKQ0JDOU8zcXdsYUNjNzlGTkdSeFh6RE96elFLaFJBTkNBQVNISWljZ09na3JXNWIzKy8yRDJTOWlZcWd2Wm56WgpLbjEzTVhvMUkzK08zTllrT0xvdzVoOGFpdkF4K1pKL3ZrWFZDQ3BFWXV3NU5oLzZHWUtTemNOZgotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=='
// 	},
// 	public: <Buffer 04 87 22 27 20 3a 09 2b 5b 96 f7 fb fd 83 d9 2f 62 62 a8 2f 66 7c d9 2a 7d 77 31 7a 35 23 7f 8e dc d6 24 38 ba 30 e6 1f 1a 8a f0 31 f9 92 7f be 45 d5 ... 15 more bytes>,
//  private: <Buffer fc 69 17 aa e6 9e 64 11 f6 89 0c 70 08 10 bd 3b 7a b0 95 a0 9c ef d1 4d 19 1c 57 cc 33 b3 cd 02>
// }

const enc = ecc.encrypt(keys.public, "hello world");
console.log('enc:', enc);
// -> enc: BNbPDdHqW1RNDglfWLdxWnTwCuAelHe5ZIuF8q5Yt12fuBp6O0KFkOwREyRGcIiMgOju5i91Kl9ggDQ9yYE4TjdE8b9fdDAW7U0tZhZJfeoOcU65KRDZrHIlrdA=

const dec = ecc.decrypt(keys.private, enc);
console.log('dec:', dec);
// -> dec: hello world
