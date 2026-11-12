const express = require('express')

const app = express()

app.get('/auth/login', (req, res) => {
  const redirect = encodeURIComponent(req.query.next)
  res.redirect(
    `https://idp.example.com/authorize?client_id=${process.env.CLIENT_ID}&response_type=token&scope=email&redirect_uri=${redirect}`
  )
})

app.listen(3000)
