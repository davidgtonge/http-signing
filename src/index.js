const fs = require("fs")
const path = require("path")
const crypto = require("crypto")
const R = require("ramda")

const cert = fs
  .readFileSync(path.join(__dirname, "../keys/cert.pem"))
  .toString()
const key = fs.readFileSync(path.join(__dirname, "../keys/key.pem")).toString()
const kid = crypto.createHash("sha256").update(cert).digest("base64")
const accessToken = crypto.randomBytes(32).toString("hex")
const method = "POST"

const dPopPlus = require("./dpop-plus")
const dPopPlus2 = require("./dpop-plus2")
const dPopPlus3 = require("./dpop-plus3")
const draftCavage = require("./draft-cavage")
const obe = require("./obe")
const obe2 = require("./obe2")
const obukv1 = require("./obuk-v1")
const obukv2 = require("./obuk-v2")

const methods = {
  dPopPlus,
  dPopPlus2,
  dPopPlus3,
  draftCavage,
  obe,
  obe2,
  obukv1,
  obukv2,
}

const iss = "https://api.tpp.com"
const url = "https://api.testbank.com/v1/payments/sepa-credit-transfers"

const headers = {
  "content-type": "application/json",
  "x-request-id": "99391c7e-ad88-49ec-a2ad-99ddcb1f7721",
  "psu-ip-address": "192.168.8.78",
  "psu-geo-location": "GEO:52.506931,13.144558",
  "psu-user-agent":
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
  date: "Fri, 3 Apr 2020 16:38:37 GMT",
}

const body = JSON.stringify({
  instructedAmount: {currency: "EUR", amount: "123.50"},
  debtorAccount: {iban: "DE40100100103307118608"},
  creditorName: "Merchant123",
  creditorAccount: {iban: "DE02100100109307118603"},
  remittanceInformationUnstructured: "Ref Number Merchant",
})

const getHeaderSize = R.compose(
  R.length,
  R.join("\n"),
  R.map(([k, v]) => `${k}:${v}`),
  R.toPairs,
)

R.compose(
  R.map(([name, obj]) => {
    const expandedHeaders = obj.sign({
      body,
      headers,
      url,
      key,
      iss,
      cert,
      method,
      kid,
      accessToken,
    })
    const size = getHeaderSize(expandedHeaders)
    console.log(`## ${name} Header size: ${size}`)
    console.log("```")
    console.log(JSON.stringify(expandedHeaders, null, 4))
    console.log("```")
  }),
  R.toPairs,
)(methods)
