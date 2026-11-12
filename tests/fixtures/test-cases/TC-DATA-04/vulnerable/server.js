const https = require('https')
const express = require('express')

const app = express()
const agent = new https.Agent({ rejectUnauthorized: false })

app.get('/api/rates', async (req, res) => {
  const response = await fetch('https://rates.example.com/v1/latest?api_key=' + process.env.RATES_KEY, { agent })
  res.json(await response.json())
})

app.listen(8080)
