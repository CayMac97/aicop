// @ts-nocheck
import User from './models/user'
import sanitize from 'mongo-sanitize'

async function login(req: any, res: any) {
  const username = sanitize(req.body.username)
  const password = sanitize(req.body.password)
  const user = await User.findOne({ username, password })
  res.json(user)
}

async function getById(req: any, res: any) {
  const user = await User.findById(req.params.id)
  res.json(user)
}

async function adminList(req: any, res: any) {
  const users = await User.find({ role: 'admin' })
  res.json(users)
}
