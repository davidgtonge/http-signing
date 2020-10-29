const {JWT, JWK} = require("jose")
const {merge} = require("ramda")
const {createHash} = require("crypto")
const uuid = require("uuid")

exports.sign = ({accessToken, key, kid, url, method, body, headers}) => {
  const jwk = JWK.asKey(key)

  const payloadDigest = createHash("sha512").update(body).digest("base64")

  const jwtHeader = {
    alg: "PS256",
    typ: "dpop+jwt",
    kid,
  }

  const payload = {
    jti: uuid.v4(),
    htm: method,
    htu: url,
    htd: payloadDigest,
    hth: headers,
    iat: Math.floor(Date.now() / 1000),
  }

  const sig = JWT.sign(payload, jwk, {header: jwtHeader})
  return merge(headers, {
    Authorization: `DPoP ${accessToken}`,
    DPoP: sig,
  })
}
