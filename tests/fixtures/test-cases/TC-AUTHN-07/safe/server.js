const crypto = require('crypto')
const fs = require('fs')
const https = require('https')
const express = require('express')
const basicAuth = require('express-basic-auth')
const { reports } = require('./reports')

const expected = process.env.REPORTS_PASSWORD
if (!expected) throw new Error('REPORTS_PASSWORD is not set')

function same (given, wanted) {
  const a = Buffer.from(String(given))
  const b = Buffer.from(wanted)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

const app = express()
app.use(basicAuth({ authorizer: (user, password) => same(user, 'reports') && same(password, expected) }))

app.get('/api/reports', (req, res) => {
  res.json(reports())
})

https
  .createServer({ key: fs.readFileSync(process.env.TLS_KEY_FILE), cert: fs.readFileSync(process.env.TLS_CERT_FILE) }, app)
  .listen(8443)
