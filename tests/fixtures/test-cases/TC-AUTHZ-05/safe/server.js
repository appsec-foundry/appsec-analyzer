const express = require('express')
const { requireLogin, requireRole } = require('./auth')
const db = require('./db')

const app = express()

app.delete('/api/users/:id', requireLogin, requireRole('admin'), async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } })
  res.status(204).end()
})

app.listen(3000)
