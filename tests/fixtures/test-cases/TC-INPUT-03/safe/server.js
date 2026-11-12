const { execFile } = require('child_process')
const net = require('net')
const express = require('express')

const app = express()

app.get('/api/ping', (req, res) => {
  const host = String(req.query.host || '')
  if (!net.isIP(host)) return res.status(400).end()
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    if (err) return res.status(502).end()
    res.type('text/plain').send(stdout)
  })
})

app.listen(3000)
