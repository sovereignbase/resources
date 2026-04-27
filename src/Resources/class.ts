import {
  CipherKey,
  Cryptographic,
  OpaqueIdentifier,
} from '@sovereignbase/cryptosuite'
import { KVStore } from '@sovereignbase/offline-kv-store'
import { decode } from '@msgpack/msgpack'
import type { CipherStoreValue } from '../.types/index.js'

export class CipherStore {
  public static offline = new KVStore<CipherStoreValue>('resources')
  public static cloud: string
  public static initialize() {}
  public static async get<T>(
    oid: OpaqueIdentifier,
    cipherKey: CipherKey
  ): Promise<T | undefined> {
    if (!Cryptographic.identifier.validate(oid)) return undefined

    let cipherValue: CipherStoreValue | undefined = await this.offline.get(oid)

    if (!cipherValue) {
      if (navigator.onLine === false) return undefined
      const res = await fetch(`https://cipher-store.sovereignbase.dev/${oid}`, {
        headers: {
          'Content-Type': 'application/msgpack',
        },
      })

      if (res.status === 404 || !res.ok) return undefined

      const raw = await res.arrayBuffer()
      try {
        cipherValue = decode(raw) as CipherStoreValue
      } catch {
        return undefined
      }
    }
    const { iv, salt, ciphertext } = cipherValue

    if (
      !(iv instanceof Uint8Array) ||
      !(salt instanceof Uint8Array) ||
      !(ciphertext instanceof ArrayBuffer)
    )
      return undefined

    let key:CipherKey
    let out:T

    try {
        out = Cryptographic.cipherMessage.decrypt()
    }
  }
}
