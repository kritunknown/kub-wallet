import {gql} from "../utils/gql.js"

export const query = gql`
  mutation AuthenticateUpdate($phone: String, $passw: String, $token: String) {
    authenticateUpdate(phone: $phone, pass: $passw, token: $token) {
      sessionId
      userId
      addr
    }
  }
`
