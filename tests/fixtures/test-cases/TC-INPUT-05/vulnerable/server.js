const express = require('express')

const app = express()

app.get('/api/preview', async (req, res) => {
  const response = await fetch(req.query.url)
  res.type('text/plain').send(await response.text())
})

app.listen(3000)
