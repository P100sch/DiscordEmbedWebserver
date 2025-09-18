export namespace CryptoJS {
    export namespace Library {
        export interface Encoder {
            stringify(wordArray: WordArray): string
        }

        export class WordArray {
            words: Array<number>
            sigBytes: number

            /**
             * Initializes a newly created word array.
             * @param {Array} words (Optional) An array of 32-bit words.
             * @param {number} sigBytes (Optional) The number of significant bytes in the words.
             * @example
             *     var wordArray = CryptoJS.lib.WordArray.create();
             *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
             *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);*/
            constructor(words: Array<number> = [], sigBytes: number | undefined = undefined) {
                words = this.words = words;

                if (sigBytes != undefined) {
                    this.sigBytes = sigBytes;
                } else {
                    this.sigBytes = words.length * 4;
                }
            }

            /**
             * Converts this word array to a string.
             * @param {Encoder} encoder
             * @return {string} The stringified word array.
             * @example
             *     var string = wordArray + '';
             *     var string = wordArray.toString();
             *     var string = wordArray.toString(CryptoJS.enc.Utf8);*/
            toString(encoder: Encoder = Encodings.Hex): string {
                return encoder.stringify(this)
            }

            /**
             * Concatenates a word array to this word array.
             * @param {WordArray} wordArray The word array to append.
             * @return {WordArray} This word array.
             * @example
             *     wordArray1.concat(wordArray2);*/
            concat(wordArray: WordArray): WordArray {
                // Shortcuts
                const thisWords = this.words;
                const thatWords = wordArray.words;
                const thisSigBytes = this.sigBytes;
                const thatSigBytes = wordArray.sigBytes;

                // Clamp excess bits
                this.clamp();

                // Concat
                if (thisSigBytes % 4) {
                    // Copy one byte at a time
                    for (let i = 0; i < thatSigBytes; i++) {
                        const thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                    }
                } else {
                    // Copy one word at a time
                    for (let j = 0; j < thatSigBytes; j += 4) {
                        thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
                    }
                }
                this.sigBytes += thatSigBytes;

                // Chainable
                return this;
            }

            /**
             * Removes insignificant bits.
             * @example
             *     wordArray.clamp();*/
            clamp() {
                // Shortcuts
                const words = this.words;
                const sigBytes = this.sigBytes;

                // Clamp
                words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
                words.length = Math.ceil(sigBytes / 4)
            }

            /**
             * Creates a copy of this word array.
             * @return {WordArray} The clone.
             * @example
             *     var clone = wordArray.clone();*/
            clone(): WordArray {
                return new WordArray(this.words.slice(0), this.sigBytes);
            }

            // noinspection JSUnusedGlobalSymbols
            /**
             * Creates a word array filled with random bytes.
             * @param {number} nBytes The number of random bytes to generate.
             * @return {WordArray} The random word array.
             * @static
             * @example
             *     var wordArray = CryptoJS.lib.WordArray.random(16);*/
            static random(nBytes: number): WordArray {
                const words = [];

                for (let i = 0; i < nBytes; i += 4) {
                    words.push(cryptoSecureRandomInt());
                }

                return new WordArray(words, nBytes);
            }
        }

        /**
         * Abstract buffered block algorithm template.
         * The property blockSize must be implemented in a concrete subtype.
         * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0*/
        export abstract class BufferedBlockAlgorithm {
            _data: WordArray
            _nDataBytes: number
            _minBufferSize = 0

            abstract blockSize: number

            protected constructor(data: WordArray, dataBytes = 0) {
                this._data = data;
                this._nDataBytes = dataBytes;
            }

            /**
             * Resets this block algorithm's data buffer to its initial state.
             * @example
             *     bufferedBlockAlgorithm.reset();*/
            reset() {
                // Initial values
                this._data = new WordArray();
                this._nDataBytes = 0;
            }

            /**
             * Adds new data to this block algorithm's buffer.
             * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
             * @example
             *     bufferedBlockAlgorithm._append('data');
             *     bufferedBlockAlgorithm._append(wordArray);*/
            _append(data: WordArray | string) {
                // Convert string to WordArray, else assume WordArray already
                if (typeof data == 'string') {
                    data = Encodings.Utf8.parse(data);
                }

                // Append
                this._data.concat(data);
                this._nDataBytes += data.sigBytes;
            }

            /**
             * Processes available data blocks.
             * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
             * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
             * @return {WordArray} The processed data.
             * @example
             *     var processedData = bufferedBlockAlgorithm._process();
             *     var processedData = bufferedBlockAlgorithm._process(!!'flush');*/
            _process(doFlush: boolean = false): WordArray {
                let processedWords: number[] = [];

                // Shortcuts
                const data = this._data;
                const dataWords = data.words;
                const dataSigBytes = data.sigBytes;
                const blockSize = this.blockSize;
                const blockSizeBytes = blockSize * 4;

                // Count blocks ready
                let nBlocksReady = dataSigBytes / blockSizeBytes;
                if (doFlush) {
                    // Round up to include partial blocks
                    nBlocksReady = Math.ceil(nBlocksReady);
                } else {
                    // Round down to include only full blocks,
                    // less the number of blocks that must remain in the buffer
                    nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
                }

                // Count words ready
                const nWordsReady = nBlocksReady * blockSize;

                // Count bytes ready
                const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

                // Process blocks
                if (nWordsReady) {
                    for (let offset = 0; offset < nWordsReady; offset += blockSize) {
                        // Perform concrete-algorithm logic
                        this._doProcessBlock(dataWords, offset);
                    }

                    // Remove processed words
                    processedWords = dataWords.splice(0, nWordsReady);
                    data.sigBytes -= nBytesReady;
                }

                // Return processed words
                return new WordArray(processedWords, nBytesReady);
            }

            abstract _doProcessBlock(M: number[], offset: number): void

            /**
             * Creates a copy of this object.
             * @return {Object} The clone.
             * @example
             *     var clone = bufferedBlockAlgorithm.clone();*/
            clone(clone: BufferedBlockAlgorithm): object {
                clone._nDataBytes = this._nDataBytes
                clone._minBufferSize = this._minBufferSize
                clone.blockSize = this.blockSize
                clone._data = this._data.clone();

                return clone;
            }
        }

        /**
         * Abstract hasher template.
         * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)*/
        export abstract class Hasher extends BufferedBlockAlgorithm {
            blockSize = 512/32
            /**
             * Configuration options.*/
            cfg: object

            /**
             * Initializes a newly created hasher.
             * @param {WordArray} data
             * @param {number} dataBytes
             * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
             * @example
             *     var hasher = CryptoJS.algo.SHA256.create();*/
            protected constructor(data: WordArray, dataBytes: number, cfg: object) {
                super(data, dataBytes);

                this.cfg = cfg;

                // Set initial values
                this.reset();
            }

            /**
             * Resets this hasher to its initial state.
             * @example
             *     hasher.reset();*/
            reset() {
                // Reset data buffer
                super.reset();

                // Perform concrete-hasher logic
                this._doReset();
            }

            abstract _doReset(): void

            /**
             * Updates this hasher with a message.
             * @param {WordArray|string} messageUpdate The message to append.
             * @return {Hasher} This hasher.
             * @example
             *     hasher.update('message');
             *     hasher.update(wordArray);*/
            update(messageUpdate: WordArray | string): Hasher {
                // Append
                this._append(messageUpdate);

                // Update the hash
                this._process();

                // Chainable
                return this;
            }

            /**
             * Finalizes the hash computation.
             * Note that the finalize operation is effectively a destructive, read-once operation.
             * @param {WordArray|string} messageUpdate (Optional) A final message update.
             * @return {WordArray} The hash.
             * @example
             *     var hash = hasher.finalize();
             *     var hash = hasher.finalize('message');
             *     var hash = hasher.finalize(wordArray);*/
            finalize(messageUpdate: WordArray | string): WordArray {
                // Final message update
                if (messageUpdate) {
                    this._append(messageUpdate);
                }

                // Perform concrete-hasher logic
                return this._doFinalize();
            }

            abstract _doFinalize(): WordArray

            clone(clone: Hasher) {
                super.clone(clone)

                clone.cfg = structuredClone(this.cfg)

                return clone;
            }
        }
    }
    import WordArray = CryptoJS.Library.WordArray;

    let crypto: Crypto;

    // Native crypto from window (Browser)
    if (typeof window !== 'undefined' && window.crypto) {
        crypto = window.crypto;
    }

    // Native crypto in web worker (Browser)
    if (typeof self !== 'undefined' && self.crypto) {
        crypto = self.crypto;
    }

    // Native crypto from worker
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        crypto = globalThis.crypto;
    }

    /* Cryptographically secure pseudorandom number generator
     * As Math.random() is cryptographically not safe to use*/
    const cryptoSecureRandomInt = function () {
        if (crypto) {
            // Use getRandomValues method (Browser)
            if (typeof crypto.getRandomValues === 'function') {
                try {
                    return crypto.getRandomValues(new Uint32Array(1))[0];
                } catch (err) {
                }
            }
        }

        throw new Error('Native crypto module could not be used to get secure random number.');
    };

    export namespace Encodings {
        import WordArray = CryptoJS.Library.WordArray;

        // noinspection JSUnusedGlobalSymbols
        /**
         * Hex encoding strategy.*/
        export const Hex = {
            // noinspection JSUnusedGlobalSymbols
            /**
             * Converts a word array to a hex string.
             * @param {WordArray} wordArray The word array.
             * @return {string} The hex string.
             * @static
             * @example
             *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);*/
            stringify: function (wordArray: WordArray): string {
                // Shortcuts
                const words = wordArray.words;
                const sigBytes = wordArray.sigBytes;

                // Convert
                const hexChars = [];
                for (let i = 0; i < sigBytes; i++) {
                    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    hexChars.push((bite >>> 4).toString(16));
                    hexChars.push((bite & 0x0f).toString(16));
                }

                return hexChars.join('');
            },

            // noinspection JSUnusedGlobalSymbols
            /**
             * Converts a hex string to a word array.
             * @param {string} hexStr The hex string.
             * @return {WordArray} The word array.
             * @static
             * @example
             *     var wordArray = CryptoJS.enc.Hex.parse(hexString);*/
            parse: function (hexStr: string): WordArray {
                // Shortcut
                const hexStrLength = hexStr.length;

                // Convert
                const words: number[] = [];
                for (let i = 0; i < hexStrLength; i += 2) {
                    words[i >>> 3] |= parseInt(hexStr.substring(i, i+2), 16) << (24 - (i % 8) * 4);
                }

                return new WordArray(words, hexStrLength / 2);
            },
        }

        /**
         * Latin1 encoding strategy.*/
        export const Latin1 = {
            /**
             * Converts a word array to a Latin1 string.
             * @param {WordArray} wordArray The word array.
             * @return {string} The Latin1 string.
             * @static
             * @example
             *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);*/
            stringify: function (wordArray: WordArray): string {
                // Shortcuts
                const words = wordArray.words;
                const sigBytes = wordArray.sigBytes;

                // Convert
                const latin1Chars = [];
                for (let i = 0; i < sigBytes; i++) {
                    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    latin1Chars.push(String.fromCharCode(bite));
                }

                return latin1Chars.join('');
            },

            /**
             * Converts a Latin1 string to a word array.
             * @param {string} latin1Str The Latin1 string.
             * @return {WordArray} The word array.
             * @static
             * @example
             *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);*/
            parse: function (latin1Str: string): WordArray {
                // Shortcut
                const latin1StrLength = latin1Str.length;

                // Convert
                const words: number[] = [];
                for (let i = 0; i < latin1StrLength; i++) {
                    words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
                }

                return new WordArray(words, latin1StrLength);
            },
        }

        // noinspection JSUnusedGlobalSymbols
        /**
         * UTF-8 encoding strategy.*/
        export const Utf8 = {
            // noinspection JSUnusedGlobalSymbols
            /**
             * Converts a word array to a UTF-8 string.
             * @param {WordArray} wordArray The word array.
             * @return {string} The UTF-8 string.
             * @static
             * @example
             *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);*/
            stringify: function (wordArray: WordArray): string {
                try {
                    // noinspection JSDeprecatedSymbols
                    return decodeURIComponent(escape(Latin1.stringify(wordArray)));
                } catch (e) {
                    throw new Error('Malformed UTF-8 data');
                }
            },

            /**
             * Converts a UTF-8 string to a word array.
             * @param {string} utf8Str The UTF-8 string.
             * @return {WordArray} The word array.
             * @static
             * @example
             *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);*/
            parse: function (utf8Str: string): WordArray {
                // noinspection JSDeprecatedSymbols
                return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
            },
        }

        // noinspection JSUnusedGlobalSymbols
        /**
         * Base64 encoding strategy.*/
        export const Base64 = {
            _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
            _reverseMap: undefined as (number[]|undefined),

            /**
             * Converts a word array to a Base64 string.
             * @param {WordArray} wordArray The word array.
             * @return {string} The Base64 string.
             * @static
             * @example
             *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);*/
            stringify: function (wordArray: WordArray): string {
                // Shortcuts
                const words = wordArray.words;
                const sigBytes = wordArray.sigBytes;
                const map = this._map;

                // Clamp excess bits
                wordArray.clamp();

                // Convert
                const base64Chars = [];
                for (let i = 0; i < sigBytes; i += 3) {
                    const byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
                    const byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
                    const byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

                    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

                    for (let j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
                        base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
                    }
                }

                // Add padding
                const paddingChar = map.charAt(64);
                if (paddingChar) {
                    while (base64Chars.length % 4) {
                        base64Chars.push(paddingChar);
                    }
                }

                return base64Chars.join('');
            },

            /**
             * Converts a Base64 string to a word array.
             * @param {string} base64Str The Base64 string.
             * @return {WordArray} The word array.
             * @static
             * @example
             *     var wordArray = CryptoJS.enc.Base64.parse(base64String);*/
            parse: function (base64Str: string): WordArray {
                // Shortcuts
                let base64StrLength = base64Str.length;
                const map = this._map;
                let reverseMap = this._reverseMap;

                if (!reverseMap) {
                    reverseMap = this._reverseMap = [];
                    for (let j = 0; j < map.length; j++) {
                        reverseMap[map.charCodeAt(j)] = j;
                    }
                }

                // Ignore padding
                const paddingChar = map.charAt(64);
                if (paddingChar) {
                    const paddingIndex = base64Str.indexOf(paddingChar);
                    if (paddingIndex !== -1) {
                        base64StrLength = paddingIndex;
                    }
                }

                // Convert
                return parseLoop(base64Str, base64StrLength, reverseMap);
            },
        };

        function parseLoop(base64Str: string, base64StrLength: number, reverseMap: number[]) {
            const words: number[] = [];
            let nBytes = 0;
            for (let i = 0; i < base64StrLength; i++) {
                if (i % 4) {
                    const bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
                    const bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
                    const bitsCombined = bits1 | bits2;
                    words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
                    nBytes++;
                }
            }
            return new WordArray(words, nBytes);
        }
    }

    export namespace Algorithms {
        import Hasher = CryptoJS.Library.Hasher;
        import Utf8 = CryptoJS.Encodings.Utf8;

        /**
         * HMAC algorithm.*/
        export class HMAC {
            _hasher: Hasher
            _oKey: WordArray
            _iKey: WordArray

            /**
             * Initializes a newly created HMAC.
             * @param {Hasher} hasher The hash algorithm to use.
             * @param {WordArray|string} key The secret key.
             * @example
             *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);*/
            constructor(hasher: Hasher, key: WordArray | string) {
                // Init hasher
                this._hasher = hasher

                // Convert string to WordArray, else assume WordArray already
                if (typeof key == 'string') {
                    key = Utf8.parse(key);
                }

                // Shortcuts
                const hasherBlockSize = hasher.blockSize;
                const hasherBlockSizeBytes = hasherBlockSize * 4;

                // Allow arbitrary length keys
                if (key.sigBytes > hasherBlockSizeBytes) {
                    key = hasher.finalize(key);
                }

                // Clamp excess bits
                key.clamp();

                // Clone key for inner and outer pads
                const oKey = this._oKey = key.clone();
                const iKey = this._iKey = key.clone();

                // Shortcuts
                const oKeyWords = oKey.words;
                const iKeyWords = iKey.words;

                // XOR keys with pad constants
                for (let i = 0; i < hasherBlockSize; i++) {
                    oKeyWords[i] ^= 0x5c5c5c5c;
                    iKeyWords[i] ^= 0x36363636;
                }
                oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

                // Set initial values
                this.reset();
            }

            /**
             * Resets this HMAC to its initial state.
             * @example
             *     hmacHasher.reset();*/
            reset() {
                // Shortcut
                const hasher = this._hasher;

                // Reset
                hasher.reset();
                hasher.update(this._iKey);
            }

            /**
             * Updates this HMAC with a message.
             * @param {WordArray|string} messageUpdate The message to append.
             * @return {HMAC} This HMAC instance.
             * @example
             *     hmacHasher.update('message');
             *     hmacHasher.update(wordArray);*/
            update(messageUpdate: WordArray | string): HMAC {
                this._hasher.update(messageUpdate);

                // Chainable
                return this;
            }

            /**
             * Finalizes the HMAC computation.
             * Note that the finalize operation is effectively a destructive, read-once operation.
             * @param {WordArray|string} messageUpdate (Optional) A final message update.
             * @return {WordArray} The HMAC.
             * @example
             *     var hmac = hmacHasher.finalize();
             *     var hmac = hmacHasher.finalize('message');
             *     var hmac = hmacHasher.finalize(wordArray);*/
            finalize(messageUpdate: WordArray | string): WordArray {
                // Shortcut
                const hasher = this._hasher;

                // Compute HMAC
                const innerHash = hasher.finalize(messageUpdate);
                hasher.reset();
                return hasher.finalize(this._oKey.clone().concat(innerHash));
            }
        }

        // Initialization and round constants tables
        let H: number[] = [];
        let K: number[] = [];

        // Compute constants
        (function () {
            function isPrime(n: number) {
                const sqrtN = Math.sqrt(n);
                for (let factor = 2; factor <= sqrtN; factor++) {
                    if (!(n % factor)) {
                        return false;
                    }
                }

                return true;
            }

            function getFractionalBits(n: number) {
                return ((n - (n | 0)) * 0x100000000) | 0;
            }

            let n = 2;
            let nPrime = 0;
            while (nPrime < 64) {
                if (isPrime(n)) {
                    if (nPrime < 8) {
                        H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
                    }
                    K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

                    nPrime++;
                }

                n++;
            }
        }());

        // Reusable object
        let W: number[] = [];

        /**
         * SHA-256 hash algorithm.*/
        export class SHA256 extends Hasher {
            // @ts-ignore
            _hash: WordArray;

            constructor() {
                super(new WordArray(), 0, {});
            }

            override _doReset() {
                this._hash = new WordArray(H.slice(0));
            }

            override _doProcessBlock(M: number[], offset: number) {
                // Shortcut
                let H = this._hash.words;

                // Working variables
                let a = H[0];
                let b = H[1];
                let c = H[2];
                let d = H[3];
                let e = H[4];
                let f = H[5];
                let g = H[6];
                let h = H[7];

                // Computation
                for (let i = 0; i < 64; i++) {
                    if (i < 16) {
                        W[i] = M[offset + i] | 0;
                    } else {
                        const gamma0x = W[i - 15];
                        const gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^
                            ((gamma0x << 14) | (gamma0x >>> 18)) ^
                            (gamma0x >>> 3);

                        const gamma1x = W[i - 2];
                        const gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                            ((gamma1x << 13) | (gamma1x >>> 19)) ^
                            (gamma1x >>> 10);

                        W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                    }

                    const ch = (e & f) ^ (~e & g);
                    const maj = (a & b) ^ (a & c) ^ (b & c);

                    const sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
                    const sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));

                    const t1 = h + sigma1 + ch + K[i] + W[i];
                    const t2 = sigma0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = (d + t1) | 0;
                    d = c;
                    c = b;
                    b = a;
                    a = (t1 + t2) | 0;
                }

                // Intermediate hash value
                H[0] = (H[0] + a) | 0;
                H[1] = (H[1] + b) | 0;
                H[2] = (H[2] + c) | 0;
                H[3] = (H[3] + d) | 0;
                H[4] = (H[4] + e) | 0;
                H[5] = (H[5] + f) | 0;
                H[6] = (H[6] + g) | 0;
                H[7] = (H[7] + h) | 0;
            }

            _doFinalize() {
                // Shortcuts
                const data = this._data;
                const dataWords = data.words;

                const nBitsTotal = this._nDataBytes * 8;
                const nBitsLeft = data.sigBytes * 8;

                // Add padding
                dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
                data.sigBytes = dataWords.length * 4;

                // Hash final blocks
                this._process();

                // Return final computed hash
                return this._hash;
            }

            clone() {
                const clone = new SHA256();
                super.clone(clone);

                clone._hash = this._hash.clone();

                return clone;
            }
        }

        /**
         * Configuration options.
         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
         * @property {Hasher} hasher The hasher to use. Default: SHA256
         * @property {number} iterations The number of iterations to perform. Default: 250000*/
        export class PBKDF2Config {
            keySize = 128 / 32
            hasher: Hasher = new SHA256()
            iterations = 250000
        }

        /**
         * Password-Based Key Derivation Function 2 algorithm.*/
        export class PBKDF2 {
            cfg: PBKDF2Config

            /**
             * Initializes a newly created key derivation function.
             * @param {PBKDF2Config} cfg (Optional) The configuration options to use for the derivation.
             * @example
             *     var kdf = CryptoJS.algo.PBKDF2.create();
             *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
             *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });*/
            constructor(cfg: PBKDF2Config = new PBKDF2Config()) {
                this.cfg = cfg
            }

            /**
             * Computes the Password-Based Key Derivation Function 2.
             * @param {WordArray|string} password The password.
             * @param {WordArray|string} salt A salt.
             * @return {WordArray} The derived key.
             * @example
             *     var key = kdf.compute(password, salt);*/
            compute(password: WordArray | string, salt: WordArray | string): WordArray {
                // Shortcut
                const cfg = this.cfg;

                // Init HMAC
                const hmac = new HMAC(cfg.hasher, password);

                // Initial values
                const derivedKey = new WordArray();
                const blockIndex = new WordArray([0x00000001]);

                // Shortcuts
                const derivedKeyWords = derivedKey.words;
                const blockIndexWords = blockIndex.words;
                const keySize = cfg.keySize;
                const iterations = cfg.iterations;

                // Generate key
                while (derivedKeyWords.length < keySize) {
                    const block = hmac.update(salt).finalize(blockIndex);
                    hmac.reset();

                    // Shortcuts
                    const blockWords = block.words;
                    const blockWordsLength = blockWords.length;

                    // Iterations
                    let intermediate = block;
                    for (let i = 1; i < iterations; i++) {
                        intermediate = hmac.finalize(intermediate);
                        hmac.reset();

                        // Shortcut
                        const intermediateWords = intermediate.words;

                        // XOR intermediate with block
                        for (let j = 0; j < blockWordsLength; j++) {
                            blockWords[j] ^= intermediateWords[j];
                        }
                    }

                    derivedKey.concat(block);
                    blockIndexWords[0]++;
                }
                derivedKey.sigBytes = keySize * 4;

                return derivedKey;
            }
        }
    }

    /**
     * Shortcut function to the hasher's object interface.
     * @param {WordArray|string} message The message to hash.
     * @return {WordArray} The hash.
     * @static
     * @example
     *     var hash = CryptoJS.SHA256('message');
     *     var hash = CryptoJS.SHA256(wordArray);*/
    export function SHA256(message: WordArray|string): WordArray {
        return (new CryptoJS.Algorithms.SHA256()).finalize(message);
    }

    /**
     * Shortcut function to the HMAC's object interface.
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     * @return {WordArray} The HMAC.
     * @static
     * @example
     *     var hmac = CryptoJS.HmacSHA256(message, key);*/
    export function HmacSHA256(message: WordArray | string, key: WordArray | string): WordArray {
        return (new Algorithms.HMAC(new Algorithms.SHA256(), key)).finalize(message);
    }

    /**
     * Computes the Password-Based Key Derivation Function 2.
     * @param {WordArray|string} password The password.
     * @param {WordArray|string} salt A salt.
     * @param {PBKDF2Config} cfg (Optional) The configuration options to use for this computation.
     * @return {WordArray} The derived key.
     * @static
     * @example
     *     var key = CryptoJS.PBKDF2(password, salt);
     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });*/
    export function PBKDF2(password: WordArray|string, salt: WordArray|string, cfg: Algorithms.PBKDF2Config = new Algorithms.PBKDF2Config()): WordArray {
        return (new Algorithms.PBKDF2(cfg)).compute(password, salt);
    }
}