// Project: @henningkerstan/jws-ed25519
// File: Ed25519PrivateKey.spec.ts
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

import { Ed25519PrivateKey } from '../src/Ed25519PrivateKey'

describe('An Ed25519PrivateKey', () => {
  it('shall correctly represent the example from RFC8037', () => {
    const key = new Ed25519PrivateKey(
      'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A'
    )
    expect(key.d).toBe('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A')
    expect(key.x).toBe('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo')

    expect(key.toString()).toBe(
      '{"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
    )

    expect(key.jwkThumbprintSHA256).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
    )
  })
})
