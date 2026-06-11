const bcrypt = require('bcryptjs');
const db = require('../db');

module.exports = {
  requireLogin(req, res, next) {
    if (!req.session.userId) return res.redirect('/auth/login');
    const user = db.get('SELECT * FROM users WHERE id = ?', req.session.userId);
    if (!user || user.banned) {
      req.session.destroy();
      return res.redirect('/auth/login');
    }
    req.user = user;
    next();
  },
  requireAdmin(req, res, next) {
    if (!req.session.userId) return res.redirect('/auth/login');
    const user = db.get('SELECT * FROM users WHERE id = ?', req.session.userId);
    if (!user || user.role !== 'admin' || user.banned) {
      return res.status(403).send('无权访问');
    }
    req.user = user;
    next();
  }
};
