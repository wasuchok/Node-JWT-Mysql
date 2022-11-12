var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
const { json } = require('express')
var jsonParser = bodyParser.json()

const bcrypt = require('bcrypt')
const saltRounds = 10

var jwt = require('jsonwebtoken')
const secret = 'LoveMyMom'

app.use(cors())

const mysql = require('mysql2')

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'login'
})

app.post('/register', jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    connection.execute(
      'INSERT INTO users (email, password, fname ,lname) VALUES (?, ?, ?, ?)',
      [req.body.email,hash,req.body.fname,req.body.lname],
      function(err, results, fields) {
        if(err) {
          res.json({status: 'error', message: err})
          return
        }
        res.json({status: 'ok'})
      }
    )
  })
})

app.post('/login', jsonParser, function(req,res,next){
  connection.execute(
    'SELECT * FROM users WHERE email = ?',
    [req.body.email],
    function(err,users,fields) {
      if(err) {
        res.json({status: 'error', message: err})
        return
      }
      if(users.length == 0){
        res.json({status: 'no user found', message: err})
        return
      }
      bcrypt.compare(req.body.password,users[0].password,function(err,islogin){
        if(islogin){
          const token = jwt.sign({ email : users[0].email }, secret, { expiresIn : '1h'})
          res.json({status: 'ok', message: 'login Successfuly', token})
        }else{
          res.json({status: 'error', message: 'login failed'})
        }
      })
    }
  )
})

app.post('/authen', jsonParser, function(req,res,next){
  try{
    const token = req.headers.authorization.split(' ')[1]
    const decoded = jwt.verify(token, secret)
    res.json({status: 'ok', decoded})
  }catch(err){
    res.json({status: 'error', message: err})
  }
})

app.listen(3333, jsonParser, function () {
  console.log('CORS-enabled web server listening on port 3333')
})