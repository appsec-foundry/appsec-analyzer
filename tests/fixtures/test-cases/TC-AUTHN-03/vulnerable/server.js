const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()
const publicKey = process.env.JWT_PUBLIC_KEY

app.get('/api/orders', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  try {
    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'], ignoreExpiration: true })
    res.json({ orders: [], user: claims.sub })
  } catch (err) {
    res.status(401).end()
  }
})

app.listen(3000)
