const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()
app.use(express.json())

const EDITABLE = ['displayName', 'email', 'language']

app.put('/api/profile', requireLogin, async (req, res) => {
  const changes = Object.fromEntries(EDITABLE.filter((field) => field in req.body).map((field) => [field, req.body[field]]))
  await db.users.update(changes, { where: { id: req.user.id } })
  res.status(204).end()
})

app.listen(3000)
