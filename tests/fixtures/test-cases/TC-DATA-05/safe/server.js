const crypto = require('crypto')
const express = require('express')
const db = require('./db')

const app = express()
app.use(express.json())

app.post('/api/payments', async (req, res) => {
  const payment = await db.payments.create({ amount: req.body.amount, providerToken: req.body.providerToken })
  console.log('payment created', payment.id)
  res.status(201).json({ id: payment.id, status: payment.status })
})

app.use((err, req, res, next) => {
  const reference = crypto.randomUUID()
  console.error('request failed', reference, err.name)
  res.status(500).json({ error: 'The request failed', reference })
})

app.listen(3000)
