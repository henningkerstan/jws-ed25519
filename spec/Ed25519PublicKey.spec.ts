// Project: @henningkerstan/jws-ed25519
// File: Ed25519PublicKey.spec.ts
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

// specification/tests for the Ed25519PublicKey class

import { Ed25519PublicKey } from '../src/Ed25519PublicKey'

describe('An Ed25519PublicKey', () => {
  it('shall correctly represent the example from RFC8037', () => {
    const publicKey = new Ed25519PublicKey(
      '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    )
    expect(publicKey.x).toBe('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo')

    expect(publicKey.toString()).toBe(
      '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
    )

    expect(publicKey.jwkThumbprintSHA256).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
    )
  })
})
