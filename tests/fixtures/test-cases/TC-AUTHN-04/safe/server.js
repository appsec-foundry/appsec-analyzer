const bcrypt = require('bcrypt')
const express = require('express')
const db = require('./db')

const app = express()
app.use(express.json())

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: 'A password needs 12 to 128 characters' })
  }
  const hash = await bcrypt.hash(password, 12)
  await db.users.insert({ email, password: hash })
  res.status(201).end()
})

app.listen(3000)
