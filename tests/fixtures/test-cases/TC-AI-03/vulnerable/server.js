const express = require('express')
const Anthropic = require('@anthropic-ai/sdk')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()
app.use(express.json())
const anthropic = new Anthropic()

const tools = [
  {
    name: 'read_document',
    description: 'Read a stored document by its ID',
    input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }
  }
]

app.post('/api/assistant', requireLogin, async (req, res) => {
  const message = await anthropic.messages.create({
    model: 'claude-sonnet-5-5',
    max_tokens: 1024,
    tools,
    messages: [{ role: 'user', content: String(req.body.question) }]
  })
  const use = message.content.find((block) => block.type === 'tool_use')
  if (!use) return res.json({ answer: message.content[0].text })
  const document = await db.documents.findByPk(use.input.id)
  res.json({ document })
})

app.listen(3000)
