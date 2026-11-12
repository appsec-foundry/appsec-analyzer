const express = require('express')
const db = require('./db')

const app = express()

app.get('/api/users/:id', async (req, res) => {
  const user = await db.users.findByPk(req.params.id)
  if (!user) return res.status(404).end()
  res.json(user)
})

app.listen(3000)
