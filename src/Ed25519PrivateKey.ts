// Project: @henningkerstan/jws-ed25519
// File: Ed25519PrivateKey.ts
//
// Copyright 2021 Henning Kerstan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Ed25519PublicKey } from './Ed25519PublicKey'
import base64url from 'base64url'
import nacl from 'tweetnacl'
import { JWSEd25519 } from './JWSEd25519'

/** An Ed25519 private key object as defined in RFC 8037, Appendix A.1. */
export class Ed25519PrivateKey extends Ed25519PublicKey {
  /** The 32 byte private key as string in base64url encoding. */
  readonly d: string

  /** Constructs a new Ed25519PrivateKey.
   * @param d The 32 byte private key as string in base64url encoding.
   */
  constructor(d?: string) {
    const s = d ? base64url.toBuffer(d) : nacl.randomBytes(32)
    const { secretKey, publicKey } = nacl.sign.keyPair.fromSeed(s)
    super(base64url(Buffer.from(publicKey)))
    this.secretKey = secretKey
    this.d = base64url(Buffer.from(s))
  }

  /** Convert to JSON in lexicographic order. */
  override toJSON() {
    return { crv: this.crv, d: this.d, kty: this.kty, x: this.x }
  }

  /** Convert to JSON string in lexicographic order. */
  override toString() {
    return JSON.stringify(this)
  }

  /** Sign a base64url encoded payload using this key. */
  sign(payload: string): JWSEd25519 {
    // base64url('{"alg":"EdDSA"}') = eyJhbGciOiJFZERTQSJ9
    const signingInput = 'eyJhbGciOiJFZERTQSJ9.' + payload

    const signature = base64url(
      Buffer.from(nacl.sign.detached(Buffer.from(signingInput), this.secretKey))
    )

    return JWSEd25519.fromPayloadAndSignature(payload, signature)
  }

  /** The internal representation of the secret key as used by TweetNaCl. */
  private secretKey: Uint8Array
}
