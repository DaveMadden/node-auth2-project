const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model.js')

const restricted = (req, res, next) => {
  console.log("MIDDLEWARE: restricted")

  //get token from header
  const token = req.headers.authorization;
  console.log(token)

  //if no token, don't allow access
  if (!token){
    return next({status: 401, message: "Token required"})
  }

  //if token then verify it's valid
  jwt.verify(token, JWT_SECRET, (err, decoded) =>{
    if(err){
      return next({status:401, message: "Token invalid"})
    }
    req.goodJWT = decoded
    next()
  })
  
  /*
  If the user does not provide a token in the Authorization header:
  status 401
  {
    "message": "Token required"
  }
  
  If the provided token does not verify:
  status 401
  {
    "message": "Token invalid"
  }
  
  Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  console.log("MIDDLEWARE: only:", role_name)
  if (req.goodJWT.role === role_name){
    next()
  }
  else{
    next({status:403, message: "This is not for you"})
  }
}


const checkUsernameExists = (req, res, next) => {
  console.log("MIDDLEWARE: check username exists")

  const { username } = req.body

  User.findBy({username})
    .then(([response]) =>{
      if (!response){
        next({status:401, message: "Invalid credentials"})
      }
      else{
        next()
      }
    })
    .catch(next)
}


const validateRoleName = (req, res, next) => {
  console.log("MIDDLEWARE: validate role name")
  
  if(!req.body.role_name || req.body.role_name.trim().length === 0){
    req.body.role_name = "student"
    return next()
  }

  req.body.role_name = req.body.role_name.trim()
  
  if (req.body.role_name === "admin" ){
    return next({status:422, message: "Role name can not be admin"})
  }

  if(req.body.role_name.length > 32){
    return next({status:422, message: "Role name can not be longer than 32 chars"})
  }

  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
