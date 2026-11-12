const express = require('express')
const session = require('express-session')
const { Issuer, generators } = require('openid-client')

const CALLBACK = 'https://app.example.com/auth/callback'

const app = express()
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))

let client
Issuer.discover('https://idp.example.com').then((issuer) => {
  client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [CALLBACK],
    response_types: ['code']
  })
})

app.get('/auth/login', (req, res) => {
  const verifier = generators.codeVerifier()
  req.session.oidc = { verifier, state: generators.state(), nonce: generators.nonce() }
  res.redirect(
    client.authorizationUrl({
      scope: 'openid email',
      code_challenge: generators.codeChallenge(verifier),
      code_challenge_method: 'S256',
      state: req.session.oidc.state,
      nonce: req.session.oidc.nonce
    })
  )
})

app.get('/auth/callback', async (req, res) => {
  const { verifier, state, nonce } = req.session.oidc || {}
  const tokens = await client.callback(CALLBACK, client.callbackParams(req), { code_verifier: verifier, state, nonce })
  req.session.regenerate(() => {
    req.session.user = tokens.claims().sub
    res.redirect('/')
  })
})

app.listen(3000)
