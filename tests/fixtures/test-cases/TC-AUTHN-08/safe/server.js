const express = require('express')
const Stripe = require('stripe')
const db = require('./db')

const secret = process.env.STRIPE_WEBHOOK_SECRET
if (!secret) throw new Error('STRIPE_WEBHOOK_SECRET is not set')
const stripe = new Stripe(process.env.STRIPE_API_KEY)

const app = express()

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, req.get('Stripe-Signature'), secret)
  } catch (err) {
    return res.status(400).end()
  }
  if (event.type === 'payment_intent.succeeded') await db.orders.markPaid(event.data.object.metadata.orderId)
  res.status(204).end()
})

app.listen(3000)
