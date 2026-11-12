const express = require('express')
const db = require('./db')

const app = express()

app.post('/webhooks/stripe', express.json(), async (req, res) => {
  const event = req.body
  if (event.type === 'payment_intent.succeeded') await db.orders.markPaid(event.data.object.metadata.orderId)
  res.status(204).end()
})

app.listen(3000)
