// Project: @henningkerstan/jws-ed25519
// File: JWSEd25519.ts
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

/** A JSON Web Signature (JWS) using the Ed25519 public-key signature system. */
export class JWSEd25519 {
  /** The protected header '{"alg":"EdDSA"}' in base64url encoding. */
  readonly protectedHeader = 'eyJhbGciOiJFZERTQSJ9'

  /** The payload in base64url encoding. */
  readonly payload: string

  /** The signature in base64url encoding. */
  readonly signature: string

  /** The compact serialization (= dot-separated concatenation of base64url encoded protected header '{"alg":"EdDSA"}', the payload and the signature). */
  readonly compactSerialization: string

  /** The compact serialization (= dot-separated concatenation of base64url encoded protected header '{"alg":"EdDSA"}', the payload and the signature). */
  toString() {
    return this.compactSerialization
  }

  /** Create a new JSON Web Signature (JWS) object using the supplied  serialization. */
  static fromCompactSerialization(jws: string) {
    const parts = jws.split('.')

    if (parts.length !== 3) {
      throw new Error('Invalid serialization: not a JWS.')
    }

    if (parts[0] !== 'eyJhbGciOiJFZERTQSJ9') {
      throw new Error('Invalid serialization: not an Ed25519 JWS.')
    }
  }

  static fromPayloadAndSignature(payload: string, signature: string) {
    return new JWSEd25519(payload, signature)
  }

  private constructor(payload: string, signature: string) {
    this.payload = payload
    this.signature = signature

    // note that base64url('{"alg":"EdDSA"}') = eyJhbGciOiJFZERTQSJ9
    this.compactSerialization =
      'eyJhbGciOiJFZERTQSJ9.' + payload + '.' + this.signature
  }
}
