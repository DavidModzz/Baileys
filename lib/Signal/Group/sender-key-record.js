import { BufferJSON } from '../../Utils/generics.js';
import { SenderKeyState } from './sender-key-state.js';
// Lo único que BufferJSON.reviver convierte: {"type":"Buffer","data":"<base64>"} u objetos con claves numéricas.
const REVIVABLE = /"data":"|\{"[\s+-]*\d/;
export class SenderKeyRecord {
    constructor(serialized) {
        this.MAX_STATES = 5;
        this.senderKeyStates = [];
        if (serialized) {
            for (const structure of serialized) {
                this.senderKeyStates.push(new SenderKeyState(null, null, null, null, null, null, structure));
            }
        }
    }
    isEmpty() {
        return this.senderKeyStates.length === 0;
    }
    getSenderKeyState(keyId) {
        if (keyId === undefined && this.senderKeyStates.length) {
            return this.senderKeyStates[this.senderKeyStates.length - 1];
        }
        return this.senderKeyStates.find(state => state.getKeyId() === keyId);
    }
    addSenderKeyState(id, iteration, chainKey, signatureKey) {
        this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, null, signatureKey));
        if (this.senderKeyStates.length > this.MAX_STATES) {
            this.senderKeyStates.shift();
        }
    }
    setSenderKeyState(id, iteration, chainKey, keyPair) {
        this.senderKeyStates.length = 0;
        this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, keyPair));
    }
    serialize() {
        return this.senderKeyStates.map(state => state.getStructure());
    }
    static deserialize(data) {
        const str = Buffer.from(data).toString('utf-8');
        // [Zeus patch] fast-sender-key-parse: el reviver se llama por cada número de los
        // arrays de claves (100k+ en registros grandes) y casi nunca convierte nada. Si el
        // texto no tiene nada convertible, JSON.parse sin reviver da exactamente lo mismo
        // (verificado con 31.863 registros reales) y es ~11x más rápido.
        const parsed = REVIVABLE.test(str) ? JSON.parse(str, BufferJSON.reviver) : JSON.parse(str);
        return new SenderKeyRecord(parsed);
    }
}
//# sourceMappingURL=sender-key-record.js.map