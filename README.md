# Hello DID:WEB and Verifiable Credentials
This repository provides a comprehensive example of DID:WEB and Verifiable Credentials using the [Decentralized Identity](https://github.com/decentralized-identity) Javascript libraries.

It also makes available code snippets and fully working examples on how to:

1. Create a private/public key pair.
2. Prepare and publish a DID:WEB
3. Create and Verify an arbitrary JWT.
3. Issue and Verify Verifiable Credentials and Verifiable Presentations. 

## Live
Test the codebase live
* https://replit.com/@StavrosKounis/W3C-VC-Hello-DID-Web?v=1

Use the commands
* Generate keys: `npm run keys`
* Create and validate JWT: `npm run jwt`
* Create and validate VCs: `npm start`

## Private and Public key pair
The [Decentralized Identity library](https://github.com/decentralized-identity) makes available the `ES256KSigner` and `EdDSASigner` signers which use `a 32 byte secp256k1 private key` and `a 64 byte Ed25519 secret key`, respectively. 

We will start with the former and introduce the latter right after. 

### Create a `secp256k1` key pair
We will use the `crypto` library to generate a random 32byte string and the `elliptic` library to create its public key. 

```javascript
import crypto from 'crypto';
import elliptic from 'elliptic';

// Request a 32 byte key
const key = crypto.randomBytes(32).toString("hex");
const ec = new elliptic.ec('secp256k1');
const prv = ec.keyFromPrivate(key,'hex').getPublic();
```

To get all the values we need for our `DID:WEB` we run:

```bash
npm run key
```

Output:
```
> node keys.js
Key (hex): 8eb63d435de4d634bc5f3df79c361e9233f55c9c2fca097758eefb018c4c61df
Public (hex): 040ed6461efcae34042cc75e1af79a844edf770c20a68f80f5f9c648fed06ae7f47898b20b0e6d5ed790298a5a02acf705d5134505aa9c4aab60f8d3c4c35e849c
x (hex): 0ed6461efcae34042cc75e1af79a844edf770c20a68f80f5f9c648fed06ae7f4
y (hex): 7898b20b0e6d5ed790298a5a02acf705d5134505aa9c4aab60f8d3c4c35e849c
x (base64): DtZGHvyuNAQsx14a95qETt93DCCmj4D1+cZI/tBq5/Q=
y (base64): eJiyCw5tXteQKYpaAqz3BdUTRQWqnEqrYPjTxMNehJw=
-- kty: EC, crv: secp256k1
```

> Important: 
>
> Keep the private `Key (hex)` in a safe location. We will use this string when we issue and sign credentials. 

### JSON Web Key (JWK)
[JWK](https://www.rfc-editor.org/rfc/rfc7517) is one of the public key representations `DID` supports and what we will use for our `DID:WEB`.

Use the `base64` values from the above output and prepare the JSON structure as it follows:
```JSON
{
  "kty":"EC",
  "crv":"secp256k1",
  "x":"DtZGHvyuNAQsx14a95qETt93DCCmj4D1+cZI/tBq5/Q=",
  "y":"eJiyCw5tXteQKYpaAqz3BdUTRQWqnEqrYPjTxMNehJw=",
}
```

## Create and publish our DID:WEB
To prepare our `DID:WEB`, we need the `JWK` structure we prepared in the previous step and an identifier. The identifier comes from the URL where we will make our `DID` available. 

For example, the `did:web:skounis.github.io` resolves to:

* https://skounis.github.io/.well-known/did.json

```JSON
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:skounis.github.io",
  "verificationMethod": [
    {
      "id": "did:web:skounis.github.io#owner",
      "type": "JsonWebKey2020",
      "controller": "did:web:skounis.github.io",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "7afa3a377b5808e4223dd62542a6e7e46ab0be95873464520193c1857ec2bb8f",
        "y": "58b050b73f31f1b8b98c0b04513257433bdad2a51188642d8b0e515fbfb3125f"
      }
    }
  ],
  "authentication": [
    "did:web:skounis.github.io#owner"
  ],
  "assertionMethod": [
    "did:web:skounis.github.io#owner"
  ]
}
```

Use the above example and:  
1. Replace the `did:web:skounis.github.io` with the `did`  that correspond to the correct domain.
2. Replace the `publicKeyJwk` part with the values we generated in the previous step
3. Save the file as `did.json` and make it publicly available under the `/.well-known/did.json` path.   
e.g.: https://skounis.github.io/.well-known/did.json

## Sign and Verify JSON Web Tokens (JWT)
Before we move to the Verifiable Credentials, we will test our DID by singing and verifying arbitrary JWTs. We will use the `did-jwt` library from [Decentralized Identity](https://github.com/decentralized-identity/did-jwt). 

### Create a signed JWT
First, we need to create a `Signer` using the `private` key (hex) we prepared before.

```javascript
import { ES256KSigner, hexToBytes } from 'did-jwt';
const key = '8eb63d435de4d634bc5f3df79c361e9233f55c9c2fca097758eefb018c4c61df';
const signer = ES256KSigner(hexToBytes(key))
```

Then we use this `signer` and create our `JWT` 

```javascript
import { createJWT } from 'did-jwt';
const jwt = await createJWT(
  { aud: 'did:web:skounis.github.io', name: 'Bob Smith' },
  { issuer: 'did:web:skounis.github.io', signer },
  { alg: 'ES256K' }
)
```

We can also decode and display a friendly version of the `JWT`:

```javascript
import { decodeJWT } from 'did-jwt';
const decoded = decodeJWT(jwt)
console.log('JWT Decoded:\n',decoded)
```

### Verify the JWT
This process resolves the `DID:WEB` and uses its public key to verify the signature of the JWT. If the signature verifies the code returns (and displays) the payload. If not it displayes an error message (exception).

We again use the `did-resolver` and `web-did-resolver` libraries from [Decentralized Identity](https://github.com/decentralized-identity).

We create a `webResolver` that uses the `DID` identifier, in this case, `did:web:skounis.github.io` and resolves its public keys. 

The library detects the signing method, constructs the public key, and verifies the signature of the JWT. 

```javascript
import { verifyJWT } from 'did-jwt';
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'

const webResolver = getResolver()
const resolver = new Resolver({
  ...webResolver
})

verifyJWT(jwt, {
  resolver,
  audience: 'did:web:skounis.github.io'
}).then(({ payload, doc, did, signer, jwt }) => {
  console.log('Verified:\n', payload)
})
```

### Put all together 
We have put all these together into the `did-jwt.js` file that
1. Prepares a `signer` 
2. Creates a signed JWT
3. Unpacks (decode) and displays the JWT
4. Resolves the `DID:WEB` and verifies the JWT

We can test it by running the following:

```bash
 npm run jwt
```

Output
```bash
> node did-jwt.js

//// JWT:
eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2NzMwMDc0MDcsImF1ZCI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8iLCJuYW1lIjoiQm9iIFNtaXRoIiwiaXNzIjoiZGlkOndlYjpza291bmlzLmdpdGh1Yi5pbyJ9.xeehr7dZocJABA5U2HZrhPvWn4c5Q4sWhz-AkFXQbHWl8KJw6V9fVa1VsG2WxdBC4RdkRJGHRmXarGoHSwiTHA

//// JWT Decoded:
 {
  header: { alg: 'ES256K', typ: 'JWT' },
  payload: {
    iat: 1673007407,
    aud: 'did:web:skounis.github.io',
    name: 'Bob Smith',
    iss: 'did:web:skounis.github.io'
  },
  signature: 'xeehr7dZocJABA5U2HZrhPvWn4c5Q4sWhz-AkFXQbHWl8KJw6V9fVa1VsG2WxdBC4RdkRJGHRmXarGoHSwiTHA',
  data: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2NzMwMDc0MDcsImF1ZCI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8iLCJuYW1lIjoiQm9iIFNtaXRoIiwiaXNzIjoiZGlkOndlYjpza291bmlzLmdpdGh1Yi5pbyJ9'
}

//// Verified:
 {
  iat: 1673007407,
  aud: 'did:web:skounis.github.io',
  name: 'Bob Smith',
  iss: 'did:web:skounis.github.io'
}
```

## Create Verifiable Credential and Verifiable Presentation.
With all the pieces in place, we are ready to work with actual W3C Verifiable Credentials and Presentations.

### Prepare the Signer
We will re-use the Signer we already created before to sign our credentials. This signer uses our private key.

### Payload
Our Verifiable Credential  needs a payload with a structure according to the [W3C Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/#jwt-encoding).

```javascript
const vcPayload = {
  sub: 'did:web:skounis.github.io',
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques'
      }
    }
  }
}
```

### Create the Verifiable Credential
Before we move with the creation of the credentials, we need to prepare our `issuer` object. A structure that carries our `did` and the `signer` we already prepared. 

```javascript
const issuer = {
    did: 'did:web:skounis.github.io',
    signer: signer
}
```

With the `issuer` and the `vcPayload` prepared, we use the `did-jwt-vc` library and create the credential as follows:

```javascript
import { createVerifiableCredentialJwt } from 'did-jwt-vc'
const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
console.log(vcJwt)
```

This gives us back our VC in the form of JWT. 

### Create the Verifiable Presentation

Similarly to the Credentials, we need to prepare a payload and then use it for creating the signed Presentation.

```javascript
import { createVerifiablePresentationJwt } from 'did-jwt-vc'

// const vpPayload: JwtPresentationPayload = {
const vpPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [vcJwt],
    foo: "bar"
  }
}

const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer)
console.log(vpJwt)
```

### Verify the Credentials and the Presentation
In this step, we will use our code to verify the issued Verifiable Credential and its Presentation. 

We will use their JWT representation as input, which is already stored in the variables `vcJwt` and `vpJwt`.

The process will.
1. Decode (unpack) the `JWT` strings
2. Resolve the `did`, in our case the `did:web:skounis.github.io`, and construct our public key.
3. Verify the signature of the credentials and display their payload. 

```javascript
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'
import { verifyCredential, verifyPresentation } from 'did-jwt-vc'

const resolver = new Resolver(getResolver())
const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log(verifiedVC)

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log(verifiedVP)
```

### Put all together 
We have put all these together into the `did-jwt-vc.js` file that
1. Prepares a `signer` 
2. Creates a Verifiable Credential and a Verifiable Presentation
4. Resolves the `DID:WEB` and verifies their JWTs

We can test it by running:

```bash
 npm run vc
```

Output
```bash
> node did-jwt-vc.js

//// Verifiable Credential:
 eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sInN1YiI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8iLCJuYmYiOjE1NjI5NTAyODIsImlzcyI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8ifQ.HdDBT9mpvCnV-vCLEygF8s1X9cGoT-nZn0ac87HiOo0WLUOPy7l5ezPTKEjf7UT7B3GokPjWAgXAEoB2DDkrVw

//// Verifiable Presentation:
 eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0owZVhBaU9pSktWMVFpZlEuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVJsWjNKbFpTSTZleUowZVhCbElqb2lRbUZqYUdWc2IzSkVaV2R5WldVaUxDSnVZVzFsSWpvaVFtRmpZMkZzWVhWeXc2bGhkQ0JsYmlCdGRYTnBjWFZsY3lCdWRXM0RxWEpwY1hWbGN5SjlmWDBzSW5OMVlpSTZJbVJwWkRwM1pXSTZjMnR2ZFc1cGN5NW5hWFJvZFdJdWFXOGlMQ0p1WW1ZaU9qRTFOakk1TlRBeU9ESXNJbWx6Y3lJNkltUnBaRHAzWldJNmMydHZkVzVwY3k1bmFYUm9kV0l1YVc4aWZRLkhkREJUOW1wdkNuVi12Q0xFeWdGOHMxWDljR29ULW5abjBhYzg3SGlPbzBXTFVPUHk3bDVlelBUS0VqZjdVVDdCM0dva1BqV0FnWEFFb0IyRERrclZ3Il0sImZvbyI6ImJhciJ9LCJpc3MiOiJkaWQ6d2ViOnNrb3VuaXMuZ2l0aHViLmlvIn0.gZJZoR0TTgeAeE_YNYzpGA9tJOg0iLRFdU3uqRPSNjgXLwBYBacbzXSHWLewHExgx0ZiltmHV3dQXmzbUYzpsg
//// Verified Credentials:
 {
  verified: true,
  payload: {
    vc: { '@context': [Array], type: [Array], credentialSubject: [Object] },
    sub: 'did:web:skounis.github.io',
    nbf: 1562950282,
    iss: 'did:web:skounis.github.io'
  },
  didResolutionResult: {
    didDocument: {
      '@context': [Array],
      id: 'did:web:skounis.github.io',
      verificationMethod: [Array],
      authentication: [Array],
      assertionMethod: [Array]
    },
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+ld+json' }
  },
  issuer: 'did:web:skounis.github.io',
  signer: {
    id: 'did:web:skounis.github.io#owner',
    type: 'JsonWebKey2020',
    controller: 'did:web:skounis.github.io',
    publicKeyJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x: 'DtZGHvyuNAQsx14a95qETt93DCCmj4D1+cZI/tBq5/Q=',
      y: 'eJiyCw5tXteQKYpaAqz3BdUTRQWqnEqrYPjTxMNehJw='
    }
  },
  jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sInN1YiI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8iLCJuYmYiOjE1NjI5NTAyODIsImlzcyI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8ifQ.HdDBT9mpvCnV-vCLEygF8s1X9cGoT-nZn0ac87HiOo0WLUOPy7l5ezPTKEjf7UT7B3GokPjWAgXAEoB2DDkrVw',
  policies: { nbf: undefined, exp: undefined, iat: undefined },
  verifiableCredential: {
    credentialSubject: { degree: [Object], id: 'did:web:skounis.github.io' },
    issuer: { id: 'did:web:skounis.github.io' },
    type: [ 'VerifiableCredential' ],
    '@context': [ 'https://www.w3.org/2018/credentials/v1' ],
    issuanceDate: '2019-07-12T16:51:22.000Z',
    proof: {
      type: 'JwtProof2020',
      jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sInN1YiI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8iLCJuYmYiOjE1NjI5NTAyODIsImlzcyI6ImRpZDp3ZWI6c2tvdW5pcy5naXRodWIuaW8ifQ.HdDBT9mpvCnV-vCLEygF8s1X9cGoT-nZn0ac87HiOo0WLUOPy7l5ezPTKEjf7UT7B3GokPjWAgXAEoB2DDkrVw'
    }
  }
}

//// Verified Presentation:
 {
  verified: true,
  payload: {
    vp: {
      '@context': [Array],
      type: [Array],
      verifiableCredential: [Array],
      foo: 'bar'
    },
    iss: 'did:web:skounis.github.io'
  },
  didResolutionResult: {
    didDocument: {
      '@context': [Array],
      id: 'did:web:skounis.github.io',
      verificationMethod: [Array],
      authentication: [Array],
      assertionMethod: [Array]
    },
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+ld+json' }
  },
  issuer: 'did:web:skounis.github.io',
  signer: {
    id: 'did:web:skounis.github.io#owner',
    type: 'JsonWebKey2020',
    controller: 'did:web:skounis.github.io',
    publicKeyJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x: 'DtZGHvyuNAQsx14a95qETt93DCCmj4D1+cZI/tBq5/Q=',
      y: 'eJiyCw5tXteQKYpaAqz3BdUTRQWqnEqrYPjTxMNehJw='
    }
  },
  jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0owZVhBaU9pSktWMVFpZlEuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVJsWjNKbFpTSTZleUowZVhCbElqb2lRbUZqYUdWc2IzSkVaV2R5WldVaUxDSnVZVzFsSWpvaVFtRmpZMkZzWVhWeXc2bGhkQ0JsYmlCdGRYTnBjWFZsY3lCdWRXM0RxWEpwY1hWbGN5SjlmWDBzSW5OMVlpSTZJbVJwWkRwM1pXSTZjMnR2ZFc1cGN5NW5hWFJvZFdJdWFXOGlMQ0p1WW1ZaU9qRTFOakk1TlRBeU9ESXNJbWx6Y3lJNkltUnBaRHAzWldJNmMydHZkVzVwY3k1bmFYUm9kV0l1YVc4aWZRLkhkREJUOW1wdkNuVi12Q0xFeWdGOHMxWDljR29ULW5abjBhYzg3SGlPbzBXTFVPUHk3bDVlelBUS0VqZjdVVDdCM0dva1BqV0FnWEFFb0IyRERrclZ3Il0sImZvbyI6ImJhciJ9LCJpc3MiOiJkaWQ6d2ViOnNrb3VuaXMuZ2l0aHViLmlvIn0.gZJZoR0TTgeAeE_YNYzpGA9tJOg0iLRFdU3uqRPSNjgXLwBYBacbzXSHWLewHExgx0ZiltmHV3dQXmzbUYzpsg',
  policies: { nbf: undefined, exp: undefined, iat: undefined },
  verifiablePresentation: {
    vp: { foo: 'bar' },
    verifiableCredential: [ [Object] ],
    holder: 'did:web:skounis.github.io',
    type: [ 'VerifiablePresentation' ],
    '@context': [ 'https://www.w3.org/2018/credentials/v1' ],
    proof: {
      type: 'JwtProof2020',
      jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0owZVhBaU9pSktWMVFpZlEuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVJsWjNKbFpTSTZleUowZVhCbElqb2lRbUZqYUdWc2IzSkVaV2R5WldVaUxDSnVZVzFsSWpvaVFtRmpZMkZzWVhWeXc2bGhkQ0JsYmlCdGRYTnBjWFZsY3lCdWRXM0RxWEpwY1hWbGN5SjlmWDBzSW5OMVlpSTZJbVJwWkRwM1pXSTZjMnR2ZFc1cGN5NW5hWFJvZFdJdWFXOGlMQ0p1WW1ZaU9qRTFOakk1TlRBeU9ESXNJbWx6Y3lJNkltUnBaRHAzWldJNmMydHZkVzVwY3k1bmFYUm9kV0l1YVc4aWZRLkhkREJUOW1wdkNuVi12Q0xFeWdGOHMxWDljR29ULW5abjBhYzg3SGlPbzBXTFVPUHk3bDVlelBUS0VqZjdVVDdCM0dva1BqV0FnWEFFb0IyRERrclZ3Il0sImZvbyI6ImJhciJ9LCJpc3MiOiJkaWQ6d2ViOnNrb3VuaXMuZ2l0aHViLmlvIn0.gZJZoR0TTgeAeE_YNYzpGA9tJOg0iLRFdU3uqRPSNjgXLwBYBacbzXSHWLewHExgx0ZiltmHV3dQXmzbUYzpsg'
    }
  }
}
```
