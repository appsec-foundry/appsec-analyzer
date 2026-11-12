const fs = require('fs')
const https = require('https')
const express = require('express')
const helmet = require('helmet')

const app = express()
app.use(helmet.hsts({ maxAge: 31536000 }))

app.get('/api/rates', async (req, res) => {
  const response = await fetch('https://rates.example.com/v1/latest', {
    headers: { Authorization: 'Bearer ' + process.env.RATES_KEY }
  })
  res.json(await response.json())
})

https
  .createServer({ key: fs.readFileSync(process.env.TLS_KEY_FILE), cert: fs.readFileSync(process.env.TLS_CERT_FILE) }, app)
  .listen(8443)
