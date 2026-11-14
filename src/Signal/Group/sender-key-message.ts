import nodeCrypto from 'node:crypto'
import { calculateSignature, verifySignature } from 'libsignal/src/curve'
import { proto } from '../../../WAProto/index.js'
import { CiphertextMessage } from './ciphertext-message'

// [Zeus patch] fast-xeddsa-sign: la firma de cada mensaje de grupo usaba curve25519-js en
// JS puro (12-19 ms por envío). Multiplicación escalar con tabla precalculada en BigInt
// (~1 ms), firma IDÉNTICA byte a byte (mismo nonce determinista). Se compara con
// calculateSignature al cargar, cada firma se verifica con Ed25519 nativo y ante
// cualquier fallo se usa calculateSignature.
type EdPoint = [bigint, bigint, bigint, bigint]

const P = (1n << 255n) - 19n
const L = (1n << 252n) + 27742317777372353535851937790883648493n
const mod = (a: bigint) => {
	const r = a % P
	return r < 0n ? r + P : r
}

function modPow(b: bigint, e: bigint) {
	let r = 1n
	b %= P
	while (e > 0n) {
		if (e & 1n) r = (r * b) % P
		b = (b * b) % P
		e >>= 1n
	}

	return r
}

const D2 = (2n * ((((-121665n * modPow(121666n, P - 2n)) % P) + P) % P)) % P

// Punto en coordenadas extendidas [X, Y, Z, T] (a = -1).
function add(p: EdPoint, q: EdPoint): EdPoint {
	const a = mod((p[1] - p[0]) * (q[1] - q[0]))
	const b = mod((p[1] + p[0]) * (q[1] + q[0]))
	const c = mod(((p[3] * D2) % P) * q[3])
	const d = mod(2n * p[2] * q[2])
	const e = b - a,
		f = d - c,
		g = d + c,
		h = b + a
	return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)]
}

const leToBig = (buf: Uint8Array) => BigInt('0x' + (Buffer.from(buf).reverse().toString('hex') || '0'))
function bigToLe(n: bigint) {
	const out = Buffer.alloc(32)
	for (let i = 0; i < 32; i++) {
		out[i] = Number(n & 0xffn)
		n >>= 8n
	}

	return out
}

// table[i][j] = j · 256^i · B, para cada byte del escalar (32 sumas por firma).
let table: EdPoint[][] | null = null
function baseTable() {
	if (table) return table
	const by = (4n * modPow(5n, P - 2n)) % P
	const u = mod(by * by - 1n),
		v = mod(((((D2 * modPow(2n, P - 2n)) % P) * by) % P) * by + 1n)
	let x = modPow((u * modPow(v, P - 2n)) % P, (P + 3n) / 8n)
	if (mod(v * x * x) !== u) x = (x * modPow(2n, (P - 1n) / 4n)) % P
	if (x & 1n) x = P - x
	let base: EdPoint = [x, by, 1n, (x * by) % P]
	const t: EdPoint[][] = []
	for (let i = 0; i < 32; i++) {
		const row: EdPoint[] = [[0n, 1n, 1n, 0n], base]
		for (let j = 2; j < 256; j++) row.push(add(row[j - 1]!, base))
		t.push(row)
		base = add(row[255]!, base)
	}

	return (table = t)
}

function scalarBaseEncode(scalarLe: Uint8Array) {
	const t = baseTable()
	let p: EdPoint = [0n, 1n, 1n, 0n]
	for (let i = 0; i < 32; i++) if (scalarLe[i]) p = add(p, t[i]![scalarLe[i]!]!)
	const zi = modPow(p[2], P - 2n)
	const x = (p[0] * zi) % P,
		y = (p[1] * zi) % P
	const enc = bigToLe(y)
	enc[31]! |= Number(x & 1n) << 7
	return enc
}

const sha512 = (...parts: Uint8Array[]) => {
	const h = nodeCrypto.createHash('sha512')
	for (const part of parts) h.update(part)
	return h.digest()
}

const ED_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
type SigningKey = { aBytes: Buffer; aBig: bigint; pubEd: Buffer; signBit: number; verifyKey: nodeCrypto.KeyObject }
const keyCache = new Map<string, SigningKey>()

function signingKey(privKey: Uint8Array) {
	const id = Buffer.from(privKey).toString('hex')
	let k = keyCache.get(id)
	if (k) return k
	const aBytes = Buffer.from(privKey)
	aBytes[0]! &= 248
	aBytes[31]! &= 127
	aBytes[31]! |= 64
	const pubEd = scalarBaseEncode(aBytes)
	k = {
		aBytes,
		aBig: leToBig(aBytes),
		pubEd,
		signBit: pubEd[31]! & 128,
		verifyKey: nodeCrypto.createPublicKey({ key: Buffer.concat([ED_SPKI_PREFIX, pubEd]), format: 'der', type: 'spki' })
	}
	if (keyCache.size >= 2000) keyCache.delete(keyCache.keys().next().value!)
	keyCache.set(id, k)
	return k
}

function fastSign(privKey: Uint8Array, msg: Uint8Array) {
	const k = signingKey(privKey)
	const r = leToBig(sha512(k.aBytes, msg)) % L
	const rEnc = scalarBaseEncode(bigToLe(r))
	const h = leToBig(sha512(rEnc, k.pubEd, msg)) % L
	const sig = Buffer.concat([rEnc, bigToLe((r + h * k.aBig) % L)])
	// Comprobación nativa (~0.1 ms) con la clave Ed25519 real; el bit de signo
	// de A va en sig[63], igual que curve25519-js.
	if (!nodeCrypto.verify(null, msg, k.verifyKey, sig)) return null
	sig[63]! |= k.signBit
	return sig
}

let fastOk = false
try {
	for (let i = 0; i < 3; i++) {
		const priv = nodeCrypto.randomBytes(32),
			msg = nodeCrypto.randomBytes(40 + i * 50)
		const ref = Buffer.from(calculateSignature(priv, msg))
		if (!ref.equals(fastSign(priv, msg) || Buffer.alloc(0))) throw new Error('firma distinta')
	}

	fastOk = true
} catch (e) {
	console.error('[Zeus patch] fast-xeddsa-sign desactivada:', (e as Error)?.message || e)
}

interface SenderKeyMessageStructure {
	id: number
	iteration: number
	ciphertext: string | Buffer
}

export class SenderKeyMessage extends CiphertextMessage {
	private readonly SIGNATURE_LENGTH = 64
	private readonly messageVersion: number
	private readonly keyId: number
	private readonly iteration: number
	private readonly ciphertext: Uint8Array
	private readonly signature: Uint8Array
	private readonly serialized: Uint8Array

	constructor(
		keyId?: number | null,
		iteration?: number | null,
		ciphertext?: Uint8Array | null,
		signatureKey?: Uint8Array | null,
		serialized?: Uint8Array | null
	) {
		super()

		if (serialized) {
			const version = serialized[0]!
			const message = serialized.slice(1, serialized.length - this.SIGNATURE_LENGTH)
			const signature = serialized.slice(-1 * this.SIGNATURE_LENGTH)
			const senderKeyMessage = proto.SenderKeyMessage.decode(message).toJSON() as SenderKeyMessageStructure

			this.serialized = serialized
			this.messageVersion = (version & 0xff) >> 4
			this.keyId = senderKeyMessage.id
			this.iteration = senderKeyMessage.iteration
			this.ciphertext =
				typeof senderKeyMessage.ciphertext === 'string'
					? Buffer.from(senderKeyMessage.ciphertext, 'base64')
					: senderKeyMessage.ciphertext
			this.signature = signature
		} else {
			const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
			const ciphertextBuffer = Buffer.from(ciphertext!)
			const message = proto.SenderKeyMessage.encode(
				proto.SenderKeyMessage.create({
					id: keyId!,
					iteration: iteration!,
					ciphertext: ciphertextBuffer
				})
			).finish()

			const signature = this.getSignature(signatureKey!, Buffer.concat([Buffer.from([version]), message]))

			this.serialized = Buffer.concat([Buffer.from([version]), message, Buffer.from(signature)])
			this.messageVersion = this.CURRENT_VERSION
			this.keyId = keyId!
			this.iteration = iteration!
			this.ciphertext = ciphertextBuffer
			this.signature = signature
		}
	}

	public getKeyId(): number {
		return this.keyId
	}

	public getIteration(): number {
		return this.iteration
	}

	public getCipherText(): Uint8Array {
		return this.ciphertext
	}

	public verifySignature(signatureKey: Uint8Array): void {
		const part1 = this.serialized.slice(0, this.serialized.length - this.SIGNATURE_LENGTH)
		const part2 = this.serialized.slice(-1 * this.SIGNATURE_LENGTH)
		const res = verifySignature(signatureKey, part1, part2)
		if (!res) throw new Error('Invalid signature!')
	}

	private getSignature(signatureKey: Uint8Array, serialized: Uint8Array): Uint8Array {
		// [Zeus patch] fast-xeddsa-sign
		if (fastOk && signatureKey?.length === 32) {
			try {
				const sig = fastSign(signatureKey, serialized)
				if (sig) return sig
			} catch {}
		}

		return Buffer.from(calculateSignature(signatureKey, serialized))
	}

	public serialize(): Uint8Array {
		return this.serialized
	}

	public getType(): number {
		return 4
	}
}
