const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()
const publicKey = process.env.JWT_PUBLIC_KEY

app.get('/api/profile', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  try {
    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
    res.json({ user: claims.sub })
  } catch (err) {
    res.status(401).end()
  }
})

app.listen(3000)
