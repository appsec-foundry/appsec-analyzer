const v8 = require('v8')
const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()

app.delete('/api/admin/users/:id', requireLogin, async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } })
  res.status(204).end()
})

app.get('/actuator/heapdump', (req, res) => {
  res.download(v8.writeHeapSnapshot())
})

app.listen(3000)
