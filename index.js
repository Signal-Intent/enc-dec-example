const jose = require('node-jose')
const fs = require('fs')

// Start by readung the keys
const alkPrivateENC = fs.readFileSync('./keys/third_party_private_enc.pem', 'utf8')
const tpPrivateSig = fs.readFileSync('./keys/third_party_private_sig.pem', 'utf8')

const alkPublicENC = fs.readFileSync('./keys/third_party_public_enc.crt', 'utf8')
const tpPublicSig = fs.readFileSync('./keys/third_party_public_sig.crt', 'utf8')

const chimneyPrivateENC = fs.readFileSync('./keys/chimney_private_enc.pem', 'utf8') 
const chimneyPrivateSig = fs.readFileSync('./keys/chimney_private_sig.pem', 'utf8')

const chimneyPublicENC = fs.readFileSync('./keys/chimney_public_enc.crt', 'utf8')
const chimneyPublicSig = fs.readFileSync('./keys/chimney_public_sig.crt', 'utf8')

async function encrypt(payload, signingPrivateKey, encryptingPublicKey) {
  const jwtthird_partySigningPrivateKey = await jose.JWK.asKey(
    signingPrivateKey,
    'pem'
  )
  const jwkEncryptingKey = await jose.JWK.asKey(encryptingPublicKey, 'pem')
  
  const token = await jose.JWS.createSign(
    {
      format: 'compact',
      fields: {
        alg: 'ES256',
      },
    },
    jwtthird_partySigningPrivateKey
  )
    .update(JSON.stringify(payload))
    .final()

  
  const encrypted = await jose.JWE.createEncrypt(
    {
      format: 'compact',
      fields: {
        alg: 'RSA-OAEP',
        enc: 'A256CBC-HS512',
      },
    },
    jwkEncryptingKey
  )
    .update(token)
    .final()


    const encryptedToken = encrypted.toString()
    return encryptedToken
}


async function decrypt(encryptedToken, signingPublicKey, encryptingPrivateKey) {
  const jwkEncryptingKey = await jose.JWK.asKey(encryptingPrivateKey, 'pem')
  const jwkSigningKey = await jose.JWK.asKey(signingPublicKey, 'pem')

  const decrypted = await jose.JWE.createDecrypt(jwkEncryptingKey)
    .decrypt(encryptedToken)

  const decryptedToken = decrypted.plaintext.toString()

  const token = await jose.JWS.createVerify(jwkSigningKey)
    .verify(decryptedToken)

  const verifiedToken = token.payload.toString()
  const data = JSON.parse(verifiedToken)

  return data
}
 

(async ()  =>{
  const externalPayload = {
    iss: 'https://external.chimney.io',
    sub: 'e8337fd9-84a3-4ff6-b45a-17d2a4cd8836',
    email: 'integration+third_partyssowithtenant@chimney.io',
    tenant_id: 'adcd7047-7da6-4280-983d-69ebc497c9f3'
  }

  const externalEncryptedToken = await encrypt(externalPayload, tpPrivateSig, chimneyPublicENC)
  console.log('External Encrypted Payload: ', externalEncryptedToken)

  const externalDecryptedToken = await decrypt(externalEncryptedToken, tpPublicSig, chimneyPrivateENC)
  console.log('External Decrypted Payload: ', externalDecryptedToken)


  const chimneyPayload = {
    iat: Math.trunc(Date.now() / 1000),
    exp: Math.trunc(Date.now() / 1000) + 60 * 60,
    session_token: 'session-token-1234567890',
    sso_dashboard_url: 'https://example.chimney.io/dashboard',
    sso_widget_url: 'https://example.chimney.io/widget',
  }

  const chimneyEncryptedToken = await encrypt(chimneyPayload, chimneyPrivateSig, alkPublicENC)
  console.log('Chimney Encrypted Payload: ', chimneyEncryptedToken)

  const chimneyDecryptedToken = await decrypt(chimneyEncryptedToken, chimneyPublicSig, alkPrivateENC)
  console.log('Chimney Decrypted Payload: ', chimneyDecryptedToken)
})();

