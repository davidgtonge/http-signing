const {createHash, createSign} = require("crypto")
const {join, prepend, map, toPairs, merge, keys, assoc, compose} = require("ramda")

exports.sign = ({key, kid, body, accessToken, headers, method, url}) => {
  const payloadDigest = createHash("sha512").update(body).digest("base64")

  const headersWithDigest = assoc("Digest", payloadDigest, headers)

  const toSign = compose(
    join("\n"),
    prepend(`(request-target): ${method} ${url}`),
    map(([key, value]) => `${key.toLowerCase()}: ${value}`),
    toPairs,
  )(headersWithDigest)

  const sig = createSign("SHA512").update(toSign).sign(key, "base64")

  const sigHeader = [
    `Signature keyid="${kid}"`,
    `algorithm="rsa-sha512"`,
    `headers="(request-target) ${keys(headersWithDigest)
      .map((key) => key.toLowerCase())
      .join(" ")}"`,
    `signature="${sig}"`,
  ].join(",")

  return merge(headersWithDigest, {
    Authorization: `Bearer ${accessToken};${sigHeader}`,
  })
}
