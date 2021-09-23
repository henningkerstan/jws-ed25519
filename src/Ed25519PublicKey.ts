// Project: @henningkerstan/jws-ed25519
// File: Ed25519PublicKey.ts
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

import base64url from 'base64url'
import { createHash } from 'crypto'
import nacl from 'tweetnacl'
import { JWSEd25519 } from './JWSEd25519'

/** An Ed25519 public key object as defined in RFC 8037, Appendix A.2. */
export class Ed25519PublicKey {
  /** The curve is Ed25519. */
  readonly crv = 'Ed25519'

  /** The key type is "octet key pair" (OKP) */
  readonly kty = 'OKP'

  /** The 32-byte public key in base64url encoding. */
  readonly x: string

  /** Construct an Ed25519PublicKey object using the supplied string as public key. */
  constructor(x: string) {
    this.x = x
  }

  /** Returns the JWK thumbprint canonicalization. */
  get jwkThumbprintCanonicalization(): string {
    return JSON.stringify({ crv: this.crv, kty: this.kty, x: this.x })
  }

  /** Convert to JSON in lexicographic order. */
  toJSON() {
    return { crv: this.crv, kty: this.kty, x: this.x }
  }

  /** Returns the JWK thumbprint canonicalization. */
  toString() {
    return this.jwkThumbprintCanonicalization
  }

  /** Returns the JSON web key (JWK) thumbprint using SHA-512. */
  get jwkThumbprint(): string {
    return this.jwkThumbprintSHA512
  }

  /** Returns the JSON web key (JWK) thumbprint using SHA-512. */
  get jwkThumbprintSHA512(): string {
    return base64url(
      Buffer.from(nacl.hash(Buffer.from(this.jwkThumbprintCanonicalization)))
    )
  }

  /** Returns the JSON web key (JWK) thumbprint using SHA-256.
   *
   * Note that this does not use 'TweetNaCl' but 'crypto' for the hash computation. TweetNaCl only supports SHA-512.*/
  get jwkThumbprintSHA256(): string {
    const hash = createHash('sha256')
    hash.update(this.jwkThumbprintCanonicalization)
    return base64url.fromBase64(hash.digest('base64'))
  }

  /** Use this key to verify a jws. */
  verify(jws: JWSEd25519): boolean {
    return false
  }
}
