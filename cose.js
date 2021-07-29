const SignTag = 98;
const Sign1Tag = 18;
const ALGO_TAGS = [
    ["RS512", -259],
    ["RS384", -258],
    ["RS256", -257],
    ["ES512", -36],
    ["ECDH-SS-512", -28],
    ["ECDH-SS", -27],
    ["ECDH-ES-512", -26],
    ["ECDH-ES", -25],
    ["ES256", -7],
    ["direct", -6],
    ["A128GCM", 1],
    ["A192GCM", 2],
    ["A256GCM", 3],
    ["SHA-256_64", 4], ["SHA-256-64", 4], ["HS256/64", 4],
    ["SHA-256", 5], ["HS256", 5],
    ["SHA-384", 6], ["HS384", 6],
    ["SHA-512", 7], ["HS512", 7],
    ["AES-CCM-16-64-128", 10], ["AES-CCM-16-128/64", 10],
    ["AES-CCM-16-64-256", 11], ["AES-CCM-16-256/64", 11],
    ["AES-CCM-64-64-128", 12], ["AES-CCM-64-128/64", 12],
    ["AES-CCM-64-64-256", 13], ["AES-CCM-64-256/64", 13],
    ["AES-MAC-128/64", 14],
    ["AES-MAC-256/64", 15],
    ["AES-MAC-128/128", 25],
    ["AES-MAC-256/128", 26],
    ["AES-CCM-16-128-128", 30], ["AES-CCM-16-128/128", 30],
    ["AES-CCM-16-128-256", 31], ["AES-CCM-16-256/128", 31],
    ["AES-CCM-64-128-128", 32], ["AES-CCM-64-128/128", 32],
    ["AES-CCM-64-128-256", 33], ["AES-CCM-64-256/128", 33]
];
const AlgToTags = new Map(ALGO_TAGS);
const AlgFromTagsMap = new Map(ALGO_TAGS.map(([alg, tag]) => [tag, alg]));
function AlgFromTags(tag) {
    const cose_name = AlgFromTagsMap.get(tag);
    if (!cose_name)
        throw new Error('Unknown algorithm, ' + tag);
    return cose_name;
}
const Translators = {
    kid: value => new TextEncoder().encode(value).buffer,
    alg: (value) => {
        if (!AlgToTags.has(value))
            throw new Error('Unknown \'alg\' parameter, ' + value);
        return AlgToTags.get(value);
    }
};
HeaderParameters = {
    partyUNonce: -22,
    static_key_id: -3,
    static_key: -2,
    ephemeral_key: -1,
    alg: 1,
    crit: 2,
    content_type: 3,
    ctyp: 3,
    kid: 4,
    IV: 5,
    Partial_IV: 6,
    counter_signature: 7
};
;
const EMPTY_BUFFER = new ArrayBuffer(0);
function TranslateHeaders(header) {
    const result = new Map();
    for (const param in header) {
        if (!HeaderParameters[param]) {
            throw new Error('Unknown parameter, \'' + param + '\'');
        }
        let value = header[param];
        if (Translators[param]) {
            value = Translators[param](header[param]);
        }
        if (value !== undefined && value !== null) {
            result.set(HeaderParameters[param], value);
        }
    }
    return result;
}
;
const KeyParameters = {
    crv: -1,
    k: -1,
    x: -2,
    y: -3,
    d: -4,
    kty: 1
};
const KeyTypes = {
    OKP: 1,
    EC2: 2,
    RSA: 3,
    Symmetric: 4
};
const KeyCrv = {
    'P-256': 1,
    'P-384': 2,
    'P-521': 3,
    X25519: 4,
    X448: 5,
    Ed25519: 6,
    Ed448: 7
};
const KeyTranslators = {
    kty: (value) => {
        if (!(KeyTypes[value])) {
            throw new Error('Unknown \'kty\' parameter, ' + value);
        }
        return KeyTypes[value];
    },
    crv: (value) => {
        if (!(KeyCrv[value])) {
            throw new Error('Unknown \'crv\' parameter, ' + value);
        }
        return KeyCrv[value];
    }
};
function TranslateKey(key) {
    const result = new Map();
    for (const param in key) {
        if (!KeyParameters[param]) {
            throw new Error('Unknown parameter, \'' + param + '\'');
        }
        let value = key[param];
        if (KeyTranslators[param]) {
            value = KeyTranslators[param](value);
        }
        result.set(KeyParameters[param], value);
    }
    return result;
}
;
function xor(a, b) {
    const buffer = new Uint8Array(Math.max(a.length, b.length));
    for (let i = 1; i <= buffer.length; ++i) {
        const av = (a.length - i) < 0 ? 0 : a[a.length - i];
        const bv = (b.length - i) < 0 ? 0 : b[b.length - i];
        buffer[buffer.length - i] = av ^ bv;
    }
    return buffer;
}
;
function runningInNode() {
    return Object.prototype.toString.call(global.process) === '[object process]';
}
;
function uint8ArrayEquals(a, b) {
    return a.length === b.length && a.every((v, i) => b[i] === v);
}

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const Tagged = cbor.Tagged;
function doSign(SigStructure, signer, alg) {
    return __awaiter(this, void 0, void 0, function* () {
        let ToBeSigned = cbor.encode(SigStructure);
        return yield crypto.subtle.sign(getAlgorithmParams(alg), signer.key, ToBeSigned);
    });
}
function create(headers, payload, signers, options) {
    return __awaiter(this, void 0, void 0, function* () {
        options = options || {};
        const p = TranslateHeaders(headers.p || {});
        const u = TranslateHeaders(headers.u || {});
        const bodyP = (p.size === 0) ? EMPTY_BUFFER : cbor.encode(p);
        const p_buffer = (p.size === 0 && options.encodep === 'empty') ? EMPTY_BUFFER : cbor.encode(p);
        if (Array.isArray(signers)) {
            if (signers.length === 0) {
                throw new Error('There has to be at least one signer');
            }
            if (signers.length > 1) {
                throw new Error('Only one signer is supported');
            }
            // TODO handle multiple signers
            const signer = signers[0];
            const externalAAD = signer.externalAAD || EMPTY_BUFFER;
            const signerPMap = TranslateHeaders(signer.p || {});
            const signerU = TranslateHeaders(signer.u || {});
            const alg = signerPMap.get(HeaderParameters.alg) || signerU.get(HeaderParameters.alg);
            const signerP = (signerPMap.size === 0) ? EMPTY_BUFFER : cbor.encode(signerPMap);
            const SigStructure = [
                'Signature',
                bodyP,
                signerP,
                externalAAD,
                payload
            ];
            const sig = yield doSign(SigStructure, signer, alg);
            const signed = [p_buffer, u, payload, [[signerP, signerU, sig]]];
            return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
        }
        else {
            const signer = signers;
            const externalAAD = signer.externalAAD || EMPTY_BUFFER;
            const alg = p.get(HeaderParameters.alg) || u.get(HeaderParameters.alg);
            const SigStructure = [
                'Signature1',
                bodyP,
                externalAAD,
                payload
            ];
            const sig = yield doSign(SigStructure, signer, alg);
            const signed = [p_buffer, u, payload, sig];
            return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
        }
    });
}
;
function getAlgorithmParams(alg) {
    const cose_name = AlgFromTags(alg);
    if (cose_name.startsWith('ES'))
        return { 'name': 'ECDSA', 'hash': 'SHA-' + cose_name.slice(2) };
    else if (cose_name.startsWith('RS'))
        return { "name": "RSASSA-PKCS1-v1_5" };
    else
        throw new Error('Unsupported algorithm, ' + cose_name);
}
function isSignatureCorrect(SigStructure, verifier, alg, sig) {
    return __awaiter(this, void 0, void 0, function* () {
        const ToBeSigned = cbor.encode(SigStructure);
        return crypto.subtle.verify(getAlgorithmParams(alg), verifier.key, sig, ToBeSigned);
    });
}
function getSigner(signers, verifier) {
    if (verifier.kid == null)
        throw new Error("Missing kid");
    const kid_buf = new TextEncoder().encode(verifier.kid);
    for (let i = 0; i < signers.length; i++) {
        const kid = signers[i][1].get(HeaderParameters.kid); // TODO create constant for header locations
        if (uint8ArrayEquals(kid_buf, kid)) {
            return signers[i];
        }
    }
}
function getCommonParameter(first, second, parameter) {
    let result;
    if (first.get) {
        result = first.get(parameter);
    }
    if (!result && second.get) {
        result = second.get(parameter);
    }
    return result;
}
/**
 * Error thrown where a message signature could not be verified.
 * This may mean that the message was forged.
 *
 * @member plaintext The decoded message, for which the signature is incorrect.
 */
class SignatureMismatchError extends Error {
    constructor(plaintext) {
        super(`Signature mismatch: The CBOR message ${JSON.stringify(plaintext)} has an invalid signature.`);
        this.name = "SignatureMismatchError";
        this.plaintext = plaintext;
    }
}
/**
 * Verify the COSE signature of a CBOR message.
 *
 * @throws {SignatureMismatchError} Will throw an exception if the signature is invalid.
 * @param payload A CBOR-encoded signed message
 * @param verifier The key used to check the signature
 * @returns The decoded message, if the signature was correct.
 */
function verify(payload, verifier, options) {
    return __awaiter(this, void 0, void 0, function* () {
        options = options || {};
        let obj = yield cbor.decodeFirst(payload);
        let type = options.defaultType ? options.defaultType : SignTag;
        if (obj instanceof Tagged) {
            if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
                throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
            }
            type = obj.tag;
            obj = obj.value;
        }
        if (!Array.isArray(obj)) {
            throw new Error('Expecting Array');
        }
        if (obj.length !== 4) {
            throw new Error('Expecting Array of lenght 4');
        }
        let [p, u, plaintext, signers] = obj;
        if (type === SignTag && !Array.isArray(signers)) {
            throw new Error('Expecting signature Array');
        }
        p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
        u = (!u.size) ? EMPTY_BUFFER : u;
        let signer = (type === SignTag ? getSigner(signers, verifier) : signers);
        if (!signer) {
            throw new Error('Failed to find signer with kid' + verifier.kid);
        }
        if (type === SignTag) {
            const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
            var [signerP, , sig] = signer;
            signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
            p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
            const signerPMap = cbor.decode(signerP);
            var alg = signerPMap.get(HeaderParameters.alg);
            var SigStructure = [
                'Signature',
                p,
                signerP,
                externalAAD,
                plaintext
            ];
        }
        else {
            const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
            var alg = getCommonParameter(p, u, HeaderParameters.alg);
            p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
            var SigStructure = [
                'Signature1',
                p,
                externalAAD,
                plaintext
            ];
            var sig = signer;
        }
        if (yield isSignatureCorrect(SigStructure, verifier, alg, sig)) {
            return plaintext;
        }
        else {
            throw new SignatureMismatchError(plaintext);
        }
    });
}

