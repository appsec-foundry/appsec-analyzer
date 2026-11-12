const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()
app.use(express.json())

app.put('/api/profile', requireLogin, async (req, res) => {
  await db.users.update(req.body, { where: { id: req.user.id } })
  res.status(204).end()
})

app.listen(3000)
