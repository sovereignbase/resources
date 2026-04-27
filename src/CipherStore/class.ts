import {
  CipherKey,
  Cryptographic,
  OpaqueIdentifier,
} from '@sovereignbase/cryptosuite'
import { KVStore } from '@sovereignbase/offline-kv-store'
import { encode, decode } from '@msgpack/msgpack'
import type { CipherStoreValue } from '../.types/index.js'
import { StationClient } from '@sovereignbase/station-client'

export class CipherStore {
  private static readonly offline = new KVStore<CipherStoreValue>(
    'cipher-store'
  )

  public static async get<T>(
    oid: OpaqueIdentifier,
    sourceKey: Uint8Array,
    publicBucketUrl: string
  ): Promise<T | undefined> {
    if (!Cryptographic.identifier.validate(oid)) return undefined

    let cipherValue: CipherStoreValue | undefined = await this.offline.get(oid)

    if (!cipherValue) {
      if (navigator.onLine === false) return undefined
      const res = await fetch(
        `${publicBucketUrl}${publicBucketUrl.endsWith('/') ? '' : '/'}${oid}`,
        {
          headers: {
            'Content-Type': 'application/msgpack',
          },
        }
      )

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

    let key: CipherKey
    let plain: Uint8Array
    let out: T

    try {
      key = (await Cryptographic.cipherMessage.deriveKey(sourceKey, { salt }))
        .cipherKey
      plain = await Cryptographic.cipherMessage.decrypt(key, { iv, ciphertext })
      out = decode(plain) as T
    } catch {
      return undefined
    }
    return out
  }

  public static async put<T extends Record<string, unknown>>(
    oid: OpaqueIdentifier,
    value: unknown,
    sourceKey: Uint8Array,
    baseStation: StationClient<T>
  ): Promise<void> {
    if (!Cryptographic.identifier.validate(oid)) throw new Error('')
    if (!(sourceKey instanceof Uint8Array)) throw new Error('')

    let bytes: Uint8Array

    try {
      bytes = encode(value)
    } catch {
      throw new Error('')
    }

    const { salt, cipherKey } =
      await Cryptographic.cipherMessage.deriveKey(sourceKey)

    const { iv, ciphertext } = await Cryptographic.cipherMessage.encrypt(
      cipherKey,
      bytes
    )

    const cipherValue: CipherStoreValue = { iv, salt, ciphertext }

    void this.offline.put(oid, cipherValue)

    void baseStation.post({ kind: 'cipherBackup', detail: cipherValue })
  }
}
