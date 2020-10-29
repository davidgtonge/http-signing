const {JWS, JWK} = require("jose")
const {merge} = require("ramda")

exports.sign = ({iss, accessToken, key, kid, body, headers}) => {
  const jwk = JWK.asKey(key)

  const jwtHeader = {
    alg: "PS256",
    kid,
    "http://openbanking.org.uk/iat": Math.floor(Date.now() / 1000),
    "http://openbanking.org.uk/iss": iss,
    "http://openbanking.org.uk/tan": "openbanking.org.uk",
    crit: [
      "http://openbanking.org.uk/iat",
      "http://openbanking.org.uk/iss",
      "http://openbanking.org.uk/tan",
    ],
  }
  const sig = JWS.sign.flattened(body, jwk, jwtHeader)
  return merge(headers, {
    Authorization: `Bearer ${accessToken}`,
    "x-jws-signature": `${sig.protected}..${sig.signature}`,
  })
}
