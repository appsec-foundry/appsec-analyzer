const express = require('express')

const app = express()
app.use(express.json())

app.post('/api/calculate', (req, res) => {
  res.json({ result: eval(req.body.expression) })
})

app.listen(3000)
