"use strict"

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k
    var desc = Object.getOwnPropertyDescriptor(m, k)
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k] } }
    }
    Object.defineProperty(o, k2, desc)
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k
    o[k2] = m[k]
}))

var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v })
}) : function(o, v) {
    o["default"] = v
})

var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod
    var result = {}
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k)
    __setModuleDefault(result, mod)
    return result
}
Object.defineProperty(exports, "__esModule", { value: true })

const libsignal = __importStar(require("libsignal"))
const WASignalGroup_1 = require("../../WASignalGroup")
const Utils_1 = require("../Utils")
const WABinary_1 = require("../WABinary")

function makeLibSignalRepository(auth) {
    // Validar que auth tenga la estructura esperada
    if (!auth || !auth.keys || !auth.creds) {
        throw new Error('Auth object must have keys and creds properties')
    }

    const storage = signalStorage(auth)
    return {
        decryptGroupMessage({ group, authorJid, msg }) {
            const senderName = jidToSignalSenderKeyName(group, authorJid)
            const cipher = new WASignalGroup_1.GroupCipher(storage, senderName)
            return cipher.decrypt(msg)
        },
        async processSenderKeyDistributionMessage({ item, authorJid }) {
            const builder = new WASignalGroup_1.GroupSessionBuilder(storage)
            const senderName = jidToSignalSenderKeyName(item.groupId, authorJid)
            const senderMsg = new WASignalGroup_1.SenderKeyDistributionMessage(null, null, null, null, item.axolotlSenderKeyDistributionMessage)
            
            // Validar que keys.get retorne un objeto válido
            const senderKeys = await auth.keys.get('sender-key', [senderName])
            const senderKey = senderKeys && senderKeys[senderName] ? senderKeys[senderName] : null
            
            if (!senderKey) {
                await storage.storeSenderKey(senderName, new WASignalGroup_1.SenderKeyRecord())
            }
            await builder.process(senderName, senderMsg)
        },
        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToSignalProtocolAddress(jid)
            const session = new libsignal.SessionCipher(storage, addr)
            let result
            
            // Verificar que existe una sesión antes de intentar descifrar
            const sessionExists = await storage.loadSession(addr.toString())
            if (!sessionExists) {
                throw new Error(`No session found for ${jid}`)
            }
            
            switch (type) {
                case 'pkmsg':
                    result = await session.decryptPreKeyWhisperMessage(ciphertext)
                    break
                case 'msg':
                    result = await session.decryptWhisperMessage(ciphertext)
                    break
                default:
                    throw new Error(`Unknown message type: ${type}`)
            }
            return result
        },
        async encryptMessage({ jid, data }) {
            const addr = jidToSignalProtocolAddress(jid)
            const cipher = new libsignal.SessionCipher(storage, addr)
            
            // Verificar que existe una sesión antes de intentar cifrar
            const sessionExists = await storage.loadSession(addr.toString())
            if (!sessionExists) {
                throw new Error(`No session found for ${jid}. You need to establish a session first.`)
            }
            
            const { type: sigType, body } = await cipher.encrypt(data)
            const type = sigType === 3 ? 'pkmsg' : 'msg'
            return { type, ciphertext: Buffer.from(body, 'binary') }
        },
        async encryptGroupMessage({ group, meId, data }) {
            const senderName = jidToSignalSenderKeyName(group, meId)
            const builder = new WASignalGroup_1.GroupSessionBuilder(storage)
            
            // Validar que keys.get retorne un objeto válido
            const senderKeys = await auth.keys.get('sender-key', [senderName])
            const senderKey = senderKeys && senderKeys[senderName] ? senderKeys[senderName] : null
            
            if (!senderKey) {
                await storage.storeSenderKey(senderName, new WASignalGroup_1.SenderKeyRecord())
            }
            const senderKeyDistributionMessage = await builder.create(senderName)
            const session = new WASignalGroup_1.GroupCipher(storage, senderName)
            const ciphertext = await session.encrypt(data)
            return {
                ciphertext,
                senderKeyDistributionMessage: senderKeyDistributionMessage.serialize(),
            }
        },
        async injectE2ESession({ jid, session }) {
            const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))
            await cipher.initOutgoing(session)
        },
        jidToSignalProtocolAddress(jid) {
            return jidToSignalProtocolAddress(jid).toString()
        },
    }
}

const jidToSignalProtocolAddress = (jid) => {
    const { user, device } = WABinary_1.jidDecode(jid)
    return new libsignal.ProtocolAddress(user, device || 0)
}

const jidToSignalSenderKeyName = (group, user) => {
    return new WASignalGroup_1.SenderKeyName(group, jidToSignalProtocolAddress(user)).toString()
}

function signalStorage({ creds, keys }) {
    // Validar que creds y keys existan
    if (!creds || !keys) {
        throw new Error('Storage requires both creds and keys objects')
    }

    return {
        loadSession: async (id) => {
            try {
                const sessions = await keys.get('session', [id])
                // Validar que sessions sea un objeto válido antes de acceder
                if (!sessions || typeof sessions !== 'object') {
                    return undefined
                }
                
                const sess = sessions[id]
                if (sess) {
                    return libsignal.SessionRecord.deserialize(sess)
                }
                return undefined
            } catch (error) {
                console.error('Error loading session:', error)
                return undefined
            }
        },
        storeSession: async (id, session) => {
            if (!session || typeof session.serialize !== 'function') {
                throw new Error('Invalid session object provided')
            }
            await keys.set({ 'session': { [id]: session.serialize() } })
        },
        isTrustedIdentity: () => {
            return true
        },
        loadPreKey: async (id) => {
            try {
                const keyId = id.toString()
                const preKeys = await keys.get('pre-key', [keyId])
                
                // Validar que preKeys sea un objeto válido
                if (!preKeys || typeof preKeys !== 'object') {
                    return undefined
                }
                
                const key = preKeys[keyId]
                if (key && key.private && key.public) {
                    return {
                        privKey: Buffer.from(key.private),
                        pubKey: Buffer.from(key.public)
                    }
                }
                return undefined
            } catch (error) {
                console.error('Error loading pre-key:', error)
                return undefined
            }
        },
        removePreKey: (id) => keys.set({ 'pre-key': { [id]: null } }),
        loadSignedPreKey: () => {
            if (!creds.signedPreKey || !creds.signedPreKey.keyPair) {
                throw new Error('Invalid signedPreKey in credentials')
            }
            
            const key = creds.signedPreKey
            return {
                privKey: Buffer.from(key.keyPair.private),
                pubKey: Buffer.from(key.keyPair.public)
            }
        },
        loadSenderKey: async (keyId) => {
            try {
                const senderKeys = await keys.get('sender-key', [keyId])
                
                // Validar que senderKeys sea un objeto válido
                if (!senderKeys || typeof senderKeys !== 'object') {
                    return undefined
                }
                
                const key = senderKeys[keyId]
                if (key) {
                    return new WASignalGroup_1.SenderKeyRecord(key)
                }
                return undefined
            } catch (error) {
                console.error('Error loading sender key:', error)
                return undefined
            }
        },
        storeSenderKey: async (keyId, key) => {
            if (!key || typeof key.serialize !== 'function') {
                throw new Error('Invalid sender key object provided')
            }
            await keys.set({ 'sender-key': { [keyId]: key.serialize() } })
        },
        getOurRegistrationId: () => {
            if (!creds.registrationId) {
                throw new Error('Registration ID not found in credentials')
            }
            return creds.registrationId
        },
        getOurIdentity: () => {
            if (!creds.signedIdentityKey) {
                throw new Error('Signed identity key not found in credentials')
            }
            
            const { signedIdentityKey } = creds
            return {
                privKey: Buffer.from(signedIdentityKey.private),
                pubKey: Utils_1.generateSignalPubKey(signedIdentityKey.public),
            }
        }
    }
}

module.exports = {
  makeLibSignalRepository
        }
