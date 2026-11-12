const express = require('express')

const app = express()
app.use(express.json())

const OPERATIONS = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  multiply: (a, b) => a * b
}

app.post('/api/calculate', (req, res) => {
  const { operation, left, right } = req.body
  if (!Object.hasOwn(OPERATIONS, operation) || !Number.isFinite(left) || !Number.isFinite(right)) {
    return res.status(400).end()
  }
  res.json({ result: OPERATIONS[operation](left, right) })
})

app.listen(3000)
