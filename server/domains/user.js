import {v4 as uuid} from "uuid"
import argon2 from "argon2"
import {createSession, sessionFor} from "./session"
import {createFlowAccount} from "../flow/create-flow-account"

const USERS = {}

const invariant = (fact, msg, ...rest) => {
  if (!fact) {
    const error = new Error(`INVARIANT ${msg}`)
    error.stack = error.stack
      .split("\n")
      .filter(d => !/at invariant/.test(d))
      .join("\n")
    console.error("\n\n---\n\n", error, "\n\n", ...rest, "\n\n---\n\n")
    throw error
  }
}

export const getUser = async(userId) =>{
  var found = await D._account.findOne({userId});
  return found? [found.userId,found] : [null, null]
}

export const getUserBy = async(key, value) =>{
  var u = {}
  u[key] = value
  var found = await D._account.findOne(u);
  return found? [found.userId,found] : [null, null]
}

export const getUserByPhone = async(phone) => {
  return await getUserBy("phone", phone)
}

export const getSession = async (data = {}) => {
  let {
    sessionId = null,
    phone = null,
    pass = null,
    name = null,
    avatar = null,
    cover = null,
    color = null,
    bio = null,
    newPass = null,
    newPhone = null
  } = data

  let userId, user

  invariant(phone, "upsertUser({ phone }) -- phone is required", data)
  ;[userId, user] = await getUserByPhone(phone)

  console.log('check return user====>',[userId, user])

  // Update users chain data here async once contracts are ready
  // eventually be smarter about this, only do it if the data changes

  // create session because apparently this function does everything
  sessionId = createSession(user.userId)

  console.log("User Found", user.userId)

  return {
    userId: user.userId,
    addr: user.addr,
    sessionId: sessionId,
  }
}

export const upsertUser = async (data = {}) => {
  let {
    sessionId = null,
    phone = null,
    pass = null,
    name = null,
    avatar = null,
    cover = null,
    color = null,
    bio = null,
    newPass = null,
    newPhone = null,
  } = data

  let userId, user
  if (sessionId == null) {
    invariant(phone, "upsertUser({ phone }) -- phone is required", data)
    invariant(pass, "upsertUser({ pass }) -- pass is required", data)
    ;[userId, user] = await getUserByPhone(phone)
  } else {
    userId = sessionFor(sessionId)
    ;[userId, user] = await getUser(userId)
  }

  if (user == null) {
    user = {
      userId: uuid(),
      vsn: 0,
      phone,
      pass: await argon2.hash(pass),
      ...(await createFlowAccount()),
    }
    userId = user.userId

    invariant(user.userId, "users require an userId")
    invariant(user.phone, "users require an phone")
    invariant(user.pass, "users require a password")
    invariant(user.addr, "users require a flow address")
    invariant(user.publicKey, "users require a publicKey")
    invariant(user.privateKey, "users require a privateKey")
    invariant(user.keyId != null, "users require a keyId")

    await D._account.create(user);
  }

  // validate passwords need to match
  if (sessionId == null) {
    invariant(await argon2.verify(user.pass, pass), "Invalid phone or password")
  }

  // update
  if (newPhone != null) user.phone = phone
  if (newPass != null) user.pass = await argon2.hash(pass)
  if (name != null) user.name = name
  if (avatar != null) user.avatar = avatar
  if (cover != null) user.cover = cover
  if (color != null) user.color = color
  if (bio != null) user.bio = bio

  if (user.name == null) user.name = null
  if (user.avatar == null)
    user.avatar = `https://avatars.onflow.org/avatar/${user.addr}.svg`
  if (user.cover == null) user.cover = `https://www.bitkub.com/static/images/poster.jpg`
  if (user.color == null) user.color = "#ff0066"
  if (user.bio == null) user.bio = ""

  user.vsn += 1


  var data_out = await D._account.findOneAndUpdate({userId}, user);
  console.log('data_out====>',{data_out,userId,user})

  // Update users chain data here async once contracts are ready
  // eventually be smarter about this, only do it if the data changes

  // create session because apparently this function does everything
  sessionId = createSession(user.userId)

  console.log("User Upserted",user)

  return {
    userId: user.userId,
    addr: user.addr,
    sessionId: sessionId,
  }
}
