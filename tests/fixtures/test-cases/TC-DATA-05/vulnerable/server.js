const express = require('express')
const db = require('./db')

const app = express()
app.use(express.json())

app.post('/api/payments', async (req, res) => {
  console.log('payment request', JSON.stringify(req.body))
  res.status(201).json(await db.payments.create(req.body))
})

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack, request: req.body })
})

app.listen(3000)
