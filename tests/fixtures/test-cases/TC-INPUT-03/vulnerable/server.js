const { exec } = require('child_process')
const express = require('express')

const app = express()

app.get('/api/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    if (err) return res.status(502).end()
    res.type('text/plain').send(stdout)
  })
})

app.listen(3000)
