export async function signIn (email, password) {
  await fetch('/api/login', { method: 'POST', credentials: 'same-origin', body: JSON.stringify({ email, password }) })
}

export async function rememberCard (card) {
  const response = await fetch('/api/payment-methods', {
    method: 'POST',
    credentials: 'same-origin',
    body: JSON.stringify({ providerToken: card.providerToken })
  })
  return (await response.json()).last4
}
