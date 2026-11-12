const express = require('express')
const { reports } = require('./reports')

const app = express()

app.get('/api/reports', (req, res) => {
  if (req.query.api_key !== process.env.REPORTS_API_KEY) return res.status(401).end()
  res.json(reports())
})

app.listen(8080)
