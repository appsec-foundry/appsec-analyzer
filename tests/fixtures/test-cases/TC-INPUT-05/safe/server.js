const express = require('express')

const app = express()
const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com'])

app.get('/api/preview', async (req, res) => {
  let url
  try {
    url = new URL(String(req.query.url))
  } catch (err) {
    return res.status(400).end()
  }
  if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) return res.status(400).end()
  const response = await fetch(url, { redirect: 'error' })
  res.type('text/plain').send(await response.text())
})

app.listen(3000)
