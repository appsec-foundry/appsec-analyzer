const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()

app.get('/api/invoices', requireLogin, async (req, res) => {
  const userId = req.query.userId || req.user.id
  res.json(await db.invoices.findAll({ where: { userId } }))
})

app.listen(3000)
