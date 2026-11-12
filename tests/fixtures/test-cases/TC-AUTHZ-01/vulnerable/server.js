const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()

app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await db.orders.findByPk(req.params.id)
  if (!order) return res.status(404).end()
  res.json(order)
})

app.listen(3000)
