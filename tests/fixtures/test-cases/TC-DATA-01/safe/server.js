const express = require('express')
const db = require('./db')

const app = express()

app.get('/api/users/:id', async (req, res) => {
  const user = await db.users.findByPk(req.params.id, { attributes: ['id', 'displayName', 'avatarUrl'] })
  if (!user) return res.status(404).end()
  res.json({ id: user.id, displayName: user.displayName, avatarUrl: user.avatarUrl })
})

app.listen(3000)
