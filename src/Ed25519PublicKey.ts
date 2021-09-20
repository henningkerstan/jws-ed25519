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

/** An Ed25519 public key object as defined in RFC 8037, Appendix A.2. */
export class Ed25519PublicKey {
  /** For Ed25519 the curve is fixed. */
  readonly crv = 'Ed25519'

  /** The key type is "octet key pair" (OKP) */
  readonly kty = 'OKP'

  /** The public key. */
  readonly x: string

  /** Construct an Ed25519PublicKey object using the supplied string as public key. */
  constructor(x: string) {
    this.x = x
  }

  /** Convert to JSON in lexicographic order. */
  toJSON() {
    return { crv: this.crv, kty: this.kty, x: this.x }
  }

  /** Returns the JWK thumbprint canonicalization. */
  toString() {
    return JSON.stringify(this)
  }
}
