function requireLogin (req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).end()
  req.user = { id: req.session.userId, role: req.session.role }
  next()
}

module.exports = { requireLogin }
