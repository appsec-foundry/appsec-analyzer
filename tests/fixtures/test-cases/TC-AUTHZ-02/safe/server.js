const v8 = require('v8')
const express = require('express')
const { requireLogin, requireRole } = require('./auth')
const db = require('./db')

const app = express()

app.delete('/api/admin/users/:id', requireLogin, requireRole('admin'), async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } })
  res.status(204).end()
})

app.get('/actuator/heapdump', requireLogin, requireRole('operator'), (req, res) => {
  res.download(v8.writeHeapSnapshot())
})

app.listen(3000)
