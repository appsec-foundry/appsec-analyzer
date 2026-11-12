const express = require('express')
const Anthropic = require('@anthropic-ai/sdk')

const app = express()
const anthropic = new Anthropic()

app.get('/help', async (req, res) => {
  const message = await anthropic.messages.create({
    model: 'claude-sonnet-5-5',
    max_tokens: 512,
    messages: [{ role: 'user', content: String(req.query.question) }]
  })
  res.send(`<div class="answer">${message.content[0].text}</div>`)
})

app.listen(3000)
