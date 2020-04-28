const { Router } = require('express')
const config = require('config')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { check, validationResult } = require('express-validator')
const User = require('../models/User')
const router = Router()


// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Wrong email').isEmail(),
    check('password', 'Minimal length 6 symbols').isLength({ min: 6 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect data when registrating'
        })
      }

      const { email, password } = req.body

      const candidate = await User.findOne({ email })

      if (candidate) {
        return res.status(400).json({ message: 'User with this email already exist.' })
      }

      const hashedPassword = await bcrypt.hash(password, 12)
      const user = new User({ email, password: hashedPassword })

      await user.save()

      res.status(201).json({ message: 'User was created.' })

    } catch (e) {
      res.status(500).json({ message: 'Something went wrong, try again!' })
    }
})

// /api/auth/login
router.post(
  '/login',
  [
    check('email', 'Enter correct email').normalizeEmail().isEmail(),
    check('password', 'Enter password').exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect data when entering'
        })
      }

      const { email, password } = req.body

      const user = await User.findOne({ email })

      if (!user) {
        return res.status(400).json({ message: "User doesn't exist" })
      }

      const isMatch = await bcrypt.compare(password, user.password)

      if (!isMatch) {
        return res.status(400).json({ message: 'Incorrect password. Try again.' })
      }

      const token = jwt.sign(
        { userId: user.id }, // data that we need to encrypt
        config.get('jwtSecret'),
        { expiresIn: '1h' } // recommended
      )

      res.json({ token, userId: user.id })

    } catch (e) {
      res.status(500).json({ message: 'Something went wrong, try again!'})
    }
})

module.exports = router
