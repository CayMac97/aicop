// @ts-nocheck
import User from './models/user'

async function login(req: any, res: any) {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password
  })
  res.json(user)
}

async function search(req: any, res: any) {
  const results = await User.find({ email: req.query.email })
  res.json(results)
}

async function deleteUser(req: any, res: any) {
  await User.deleteOne({ _id: req.body.id })
}

async function bulkQuery(req: any, res: any) {
  const results = await User.find(req.body)
  res.json(results)
}
