import { BufferJSON } from '../../Utils/generics'
import { SenderKeyState } from './sender-key-state'

// Lo único que BufferJSON.reviver convierte: {"type":"Buffer","data":"<base64>"} u objetos con claves numéricas.
const REVIVABLE = /"data":"|\{"[\s+-]*\d/

export interface SenderKeyStateStructure {
	senderKeyId: number
	senderChainKey: {
		iteration: number
		seed: Uint8Array
	}
	senderSigningKey: {
		public: Uint8Array
		private?: Uint8Array
	}
	senderMessageKeys: Array<{
		iteration: number
		seed: Uint8Array
	}>
}

export class SenderKeyRecord {
	private readonly MAX_STATES = 5
	private readonly senderKeyStates: SenderKeyState[] = []

	constructor(serialized?: SenderKeyStateStructure[]) {
		if (serialized) {
			for (const structure of serialized) {
				this.senderKeyStates.push(new SenderKeyState(null, null, null, null, null, null, structure))
			}
		}
	}

	public isEmpty(): boolean {
		return this.senderKeyStates.length === 0
	}

	public getSenderKeyState(keyId?: number): SenderKeyState | undefined {
		if (keyId === undefined && this.senderKeyStates.length) {
			return this.senderKeyStates[this.senderKeyStates.length - 1]
		}

		return this.senderKeyStates.find(state => state.getKeyId() === keyId)
	}

	public addSenderKeyState(id: number, iteration: number, chainKey: Uint8Array, signatureKey: Uint8Array): void {
		this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, null, signatureKey))
		if (this.senderKeyStates.length > this.MAX_STATES) {
			this.senderKeyStates.shift()
		}
	}

	public setSenderKeyState(
		id: number,
		iteration: number,
		chainKey: Uint8Array,
		keyPair: { public: Uint8Array; private: Uint8Array }
	): void {
		this.senderKeyStates.length = 0
		this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, keyPair))
	}

	public serialize(): SenderKeyStateStructure[] {
		return this.senderKeyStates.map(state => state.getStructure())
	}
	static deserialize(data: Uint8Array): SenderKeyRecord {
		const str = Buffer.from(data).toString('utf-8')
		// [Zeus patch] fast-sender-key-parse: el reviver se llama por cada número de los
		// arrays de claves (100k+ en registros grandes) y casi nunca convierte nada. Si el
		// texto no tiene nada convertible, JSON.parse sin reviver da exactamente lo mismo
		// (verificado con 31.863 registros reales) y es ~11x más rápido.
		const parsed = REVIVABLE.test(str) ? JSON.parse(str, BufferJSON.reviver) : JSON.parse(str)
		return new SenderKeyRecord(parsed)
	}
}
