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
      name: 'propose_refund',
      parameters: { type: 'object', properties: { orderId: { type: 'string' } }, required: ['orderId'] }
    }
  }
]

app.post('/api/support/tickets/:id/answer', async (req, res) => {
  const ticket = await db.tickets.findByPk(req.params.id)
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: 'You answer support tickets and may propose a refund for staff to approve.' },
      { role: 'user', content: ticket.body }
    ],
    tools
  })
  const message = completion.choices[0].message
  for (const call of message.tool_calls || []) {
    if (call.function.name !== 'propose_refund') continue
    const { orderId } = JSON.parse(call.function.arguments)
    const order = await db.orders.findOne({ where: { id: String(orderId), customerId: ticket.customerId } })
    if (order) await db.refundRequests.create({ orderId: order.id, ticketId: ticket.id, status: 'awaiting_approval' })
  }
  res.json({ answer: message.content })
})

app.listen(3000)
