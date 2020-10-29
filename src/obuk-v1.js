const {JWS, JWK} = require("jose")
const {merge} = require("ramda")

exports.sign = ({iss, key, kid, accessToken, body, headers}) => {
  const jwk = JWK.asKey(key)

  const jwtHeader = {
    b64: false,
    alg: "PS256",
    kid,
    "http://openbanking.org.uk/iat": Math.floor(Date.now() / 1000),
    "http://openbanking.org.uk/iss": iss,
    crit: [
      "b64",
      "http://openbanking.org.uk/iat",
      "http://openbanking.org.uk/iss",
    ],
  }
  const sig = JWS.sign.flattened(body, jwk, jwtHeader)
  return merge(headers, {
    Authorization: `Bearer ${accessToken}`,
    "x-jws-signature": `${sig.protected}..${sig.signature}`,
  })
}

exports.verify = ({})