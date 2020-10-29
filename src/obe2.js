const {createHash} = require("crypto")
const {JWK, JWS} = require("jose")
const thumbprint = require("jose/lib/jwk/thumbprint")
const {join, prepend, merge, assoc, map, toPairs, keys, compose} = require("ramda")

exports.sign = ({key, cert, body, accessToken, headers, method, url}) => {
  const jwk = JWK.asKey(key)

  const payloadDigest = createHash("sha512").update(body).digest("base64")
  const headersWithDigest = assoc("Digest", payloadDigest, headers)

  const sigDPars = compose(
    prepend("(request-target)"),
    map((key) => key.toLowerCase()),
    keys,
  )(headersWithDigest)

  const jwtHeader = {
    alg: "RS256",
    "x5t#S256": thumbprint["x5t#S256"](cert),
    sigT: new Date().toISOString(),
    sigD: {
      pars: sigDPars,
      mId: "http://uri.etsi.org/19182/HttpHeaders",
    },
    crit: ["sigT", "sigD"],
  }

  const toSign = compose(
    join("\n"),
    prepend(`(request-target): ${method} ${url}`),
    map(([key, value]) => `${key.toLowerCase()}: ${value}`),
    toPairs,
  )(headersWithDigest)

  const sig = JWS.sign.flattened(toSign, jwk, jwtHeader)
  return merge(headers, {
    Authorization: `Bearer ${accessToken}`,
    "x-jws-signature": `${sig.protected}..${sig.signature}`,
  })
}
