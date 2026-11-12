const crypto = require('crypto')
const express = require('express')
const db = require('./db')

const app = express()
app.use(express.json())

app.post('/api/register', async (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
  await db.users.insert({ email: req.body.email, password: hash })
  res.status(201).end()
})

app.listen(3000)
