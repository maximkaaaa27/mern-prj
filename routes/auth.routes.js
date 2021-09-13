const { Router } = require('express')
const router = Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')
const User = require('../models/User')


// /api/auth/register

router.post(
  '/register', 
  [

    check('email', 'Incorrect email').isEmail(),
    check('password', 'Min length password 6 symbols').isLength({min:6})
  ],
  async (req, res) => {
  try {

    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect registration data'
      })
    }

    const { email, password } = req.body

    const candidate = await User.findOne({ email })

    if (candidate) {
      res.status(400).json({ message: 'Пользователь уже создан'})
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ email, password: hashedPassword})

    await user.save()

    res.status(201).json({ message: 'Пользователь успешно создан'})

  } catch(e) {
    res.status(500).json({message: 'Ooops... Something wrong. Try again'})
  }
})

router.post(
  '/login',
  [
    check('email', 'Enter correct email').normalizeEmail().isEmail(),
    check('password', "Enter password").exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req) 
        if (!errors.isEmpty()) {
          return res.status(400).json({
            errors: errors.array(),
            message: 'Incorrect enter data'
          })
        }
  
      const { email, password } = req.body

      const user = await User.findOne({ email })

      if(!user) {
        return res.status(400).json({ message: 'User not found' })
      }
      const token = jwt.sign(
        { userId: user.id },
        config.get('jwtSecret'),
        { expiresIn: '1h' }

      )



      const isMatch = await bcrypt.compare(password, user.password)

      if (!isMatch) {
        return res.status(400).json({ message: 'Wrong password, try again'})
      }

      res.json({ token, userId: user.id })
  
    } catch(e) {
      res.status(500).json({message: 'Something wrong. Try again'})
    }
})

module.exports = router