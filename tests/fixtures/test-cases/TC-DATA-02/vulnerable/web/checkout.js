export async function signIn (email, password) {
  const response = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) })
  const { token } = await response.json()
  localStorage.setItem('token', token)
}

export function rememberCard (card) {
  localStorage.setItem('card', JSON.stringify({ number: card.number, expiry: card.expiry, cvc: card.cvc }))
}
