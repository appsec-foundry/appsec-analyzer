const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()

app.get('/api/profile', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const claims = jwt.decode(token)
  if (!claims) return res.status(401).end()
  res.json({ user: claims.sub })
})

app.listen(3000)
