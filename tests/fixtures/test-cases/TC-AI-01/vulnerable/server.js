const express = require('express')
const OpenAI = require('openai')
const db = require('./db')

const app = express()
app.use(express.json())
const openai = new OpenAI()

const tools = [
  {
    type: 'function',
    function: {
      name: 'refund_order',
      parameters: { type: 'object', properties: { orderId: { type: 'string' } }, required: ['orderId'] }
    }
  }
]

app.post('/api/support/tickets/:id/answer', async (req, res) => {
  const ticket = await db.tickets.findByPk(req.params.id)
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: 'You answer support tickets and may refund orders.' },
      { role: 'user', content: ticket.body }
    ],
    tools
  })
  const message = completion.choices[0].message
  for (const call of message.tool_calls || []) {
    if (call.function.name === 'refund_order') await db.orders.refund(JSON.parse(call.function.arguments).orderId)
  }
  res.json({ answer: message.content })
})

app.listen(3000)
