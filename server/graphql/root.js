import request from "request"
import * as CONFIG from "../config"
import * as db from "../domains/user"
import {sessionFor} from "../domains/session"
import {createHandshake, handshakeFor} from "../domains/handshake"
import {
  authorizationFor,
  approveAuthorization as approveAuthorizationFor,
  declineAuthorization as declineAuthorizationFor,
} from "../domains/authorization"

const CHAR = "0123456789abcdef"
const randChar = () => CHAR[~~(Math.random() * CHAR.length)]
const rand = length => Array.from({length}, randChar).join("")
const random = (minimum, maximum)=> {
        return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}


const invariant = (fact, msg, ...rest) => {
  if (!fact) {
    const error = new Error(`GQL INVARIANT ${msg}`)
    error.stack = error.stack
      .split("\n")
      .filter(d => !/at invariant/.test(d))
      .join("\n")
    console.error("\n\n---\n\n", error, "\n\n", ...rest, "\n\n---\n\n")
    throw error
  }
}

// Creates or Updates an user account
export const upsertUser = async ({input}) => {
  console.log("GQL -- mutation/upsertUser", {input})
  const {userId} = await db.upsertUser(input)
  invariant(userId, "failed to upsert user")

  const [_, user] = await db.getUser(userId)
  invariant(user, `couldnt not find user with id of "${userId}"`)

  return user
}

export const requestOtp = async ({phone}) => {

  console.log("GQL -- mutation/requestOtp", {phone})
  //invariant(phone, "phone required")
  var token = rand(8)
  var otp = random(111111,999999)
  var check = await R.getAsync("CK:"+phone);
  console.log({check})
  if(check){
    console.log("GQL -- mutation/requestOtp DEL", {phone, otp, token, data_key})
    R.del("CK:"+phone,()=>{});
    R.del("OTP:"+check,()=>{});
  }
  R.setAsync("CK:"+phone,token);
  R.setAsync("OTP:"+token,phone+':'+otp);    


  var data_key = await R.getAsync("OTP:"+token);
  console.log({data_key})
  console.log("GQL -- mutation/requestOtp SET", {phone, otp, token, data_key})

  // return the session, plus the user

  return {
    token,
    step:0
  }
}

export const authenticateOtp = async ({phone, otp, token}) => {
  console.log("GQL -- mutation/authenticateOtp", {phone, token})
  invariant(phone, "phone required")
  invariant(token, "token required")

  var token_sess = rand(20)
  var check = await R.getAsync("OTP:"+token);

  console.log({check})
  invariant(check, "invalid token") 

  if(check){
    var raw = check.split(':')
    var valid = (raw[0]==phone && raw[1]==otp)
    if(valid){
      console.log("GQL -- mutation/authenticateOtp DEL", {phone, token, token_sess,valid, raw})
      R.del("CK:"+phone,()=>{});
      R.del("OTP:"+token,()=>{});

      const check_arr = await db.getUserByPhone(phone)
      console.log("GQL -- mutation/authenticateOtp getUserByPhone", {phone, token, token_sess,check_arr})
      if(check_arr[0]){
        console.log("GQL -- mutation/authenticateOtp Found", {phone, token, token_sess,check_arr})
        // create new user or authenticate old user (returns a session)
        const session = await db.getSession({phone})
        invariant(session, "failed to create session")  

        const user = await db.getUser(session.userId)
        invariant(user, "failed to get user for newly created sessionId")
        console.log("GQL -- mutation/authenticateOtp response", {phone, token, token_sess, user})
        // return the session, plus the user
        return {
          token:token_sess,
          step:3,
          sessionId:session.sessionId
        } 
      }else{
        R.setAsync("CKSESS:"+phone,token_sess);
        R.setAsync("SESS:"+token_sess,phone);   
        return {
          token:token_sess,
          step:2
        } 
      }
     
    }else{
      return {
        token:token_sess,
        step:0
      }
    }
  }
}

export const authenticateUpdate = async ({phone, pass, token}) => {

  console.log("GQL -- mutation/authenticateUpdate", {phone, pass, token})
  invariant(phone, "phone required")
  invariant(pass, "pass required")
  invariant(token, "token required")

  var check = await R.getAsync("CK:"+phone);
  var token_sess = await R.getAsync("CKSESS:"+phone);
  var check_phone = await R.getAsync("SESS:"+token_sess);  


  invariant(token_sess==token, "token invalid")
  invariant(check_phone==phone, "data invalid")

  // create new user or authenticate old user (returns a session)
  const session = await db.upsertUser({phone, pass})
  invariant(session, "failed to create session")  


  // get the user from the userId inside the session
  const user = await db.getUser(session.userId)
  console.log("GQL -- mutation/authenticateUpdate getUser", {user})
  invariant(user, "failed to get user for newly created sessionId")

  // return the session, plus the user
  return {
    ...session,
    user: await db.getUser(session.userId),
  }
}

export const authenticate = async ({phone, pass}) => {

  console.log("GQL -- mutation/authenticate", {phone, pass})
  invariant(phone, "phone required")
  invariant(pass, "pass required")

  // create new user or authenticate old user (returns a session)
  const session = await db.upsertUser({phone, pass})
  invariant(session, "failed to create session")  



  // get the user from the userId inside the session
  const user = await db.getUser(session.userId)
  invariant(user, "failed to get user for newly created sessionId")

  // return the session, plus the user
  return {
    ...session,
    user: await db.getUser(session.userId),
  }
}

// Returns the users info for a given sessionId
export const me = async ({sessionId}) => {
  console.log("GQL -- query/me", {sessionId})
  invariant(sessionId, "sessionId required")

  // exchange userId from sessionId
  const userId = sessionFor(sessionId)
  invariant(userId, "Invalid SessionId")

  // get users data from the userId we got from the session
  const [_, user] = await db.getUser(userId)
  invariant(user, "could not find user")

  // return the user
  return user
}

// Generates a handshake and associated handshakeId
// handshakeId will be used when FCL attempts to fetch hooks
// and private data
export const genHandshake = ({input}) => {
  console.log("GQL -- mutation/genHandshake", {input})
  const {sessionId, l6n, nonce, scope} = input
  invariant(sessionId, "sessionId required")
  invariant(l6n, "l6n required")
  invariant(nonce, "nonce required")

  // exchange sessionId for userId
  const userId = sessionFor(sessionId)
  invariant(userId != null, "Invalid SessionId")

  // generate handshakeId for given user and dapp
  // and return it
  return createHandshake({userId, l6n, nonce, scope})
}

// Returns the handshake info for a given sessionId and handshakeId
// sessionId is only used to verify if the user is authenticated
// while the handshakeId is used to retrieve the relevant information
// the frontend needs inorder to respond to FCLs challenge
export const handshake = async({sessionId, handshakeId}) => {
  console.log("GQL -- query/handshake", {sessionId, handshakeId})
  invariant(sessionId, "sessionId required")
  invariant(handshakeId, "handshakeId required")

  // exchange sessionId for userId so we know the session is valid
  const userId = sessionFor(sessionId)
  invariant(userId, "Invalid SessionId")

  // exchange handshakeId for the handshakes data
  const handshake = handshakeFor(handshakeId)
  invariant(handshake, "Invalid HandshakeId")

  // use userId inside of handshake to get users data
  const [_, user] = await db.getUser(handshake.userId)
  invariant(user, "could not find user")
  invariant(
    userId === user.userId,
    "Session User and Handshake User did not match"
  )

  // augment handshake with additional provider data
  // and return it, because thats what this function is supposed to do
  return {
    ...handshake, // includes handshakeId, exp, l6n, and nonce
    addr: user.addr, // The users flow address
    paddr: CONFIG.PID, // Will eventually be the providers onchain address that FCL can use to find more info about it
    hooks: CONFIG.HOST + "/flow/hooks", // Where FCL will get hook information
  }
}

// Returns the details of an authorization
export const authorization = async ({sessionId, authorizationId}) => {
  console.log("GQL -- query/authorization", {sessionId, authorizationId})
  invariant(sessionId, "sessionId required")
  invariant(authorizationId, "authorizationId required")

  // exchange sessionId for userId so we know the session is valid
  const userId = sessionFor(sessionId)
  invariant(userId, "Invalid SessionId")

  // get authorization for supplied authorizationId
  const authorization = authorizationFor(authorizationId)
  invariant(authorization, "count not find authorization")
  invariant(
    authorization.transaction,
    "count not find authorization.transaction",
    {authorization}
  )
  invariant(authorization.status, "count not find authorization.status", {
    authorization,
  })

  return {
    authorizationId,
    transaction: JSON.stringify(authorization.transaction),
    status: authorization.status,
  }
}

export const approveAuthorization = async ({input}) => {
  console.log("GQL -- mutation/approveAuthorization", input)
  const {authorizationId, sessionId} = input
  invariant(sessionId, "sessionId required")
  invariant(authorizationId, "authorizationId required")

  // exchange sessionId for userId so we know the session is valid
  const userId = sessionFor(sessionId)
  invariant(userId, "Invalid SessionId")

  return approveAuthorizationFor({authorizationId})
}

export const declineAuthorization = async ({input}) => {
  console.log("GQL -- mutation/approveAuthorization", input)
  const {authorizationId, sessionId} = input
  invariant(sessionId, "sessionId required")
  invariant(authorizationId, "authorizationId required")

  // exchange sessionId for userId so we know the session is valid
  const userId = sessionFor(sessionId)
  invariant(userId, "Invalid SessionId")

  return declineAuthorizationFor({authorizationId})
}

export const config = async () => {
  console.log("GQL -- query/config")
  return {
    accessNode: CONFIG.ACCESS_NODE,
    host: CONFIG.HOST,
    icon: CONFIG.ICON,
    name: CONFIG.NAME,
    origin: CONFIG.ORIGIN,
    pid: CONFIG.PID,
    port: CONFIG.PORT,
  }
}
