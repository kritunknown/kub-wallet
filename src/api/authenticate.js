import {gql} from "../utils/gql.js"

export const query = gql`
  mutation Authenticate($phone: String, $passw: String) {
    authenticate(phone: $phone, pass: $passw) {
      sessionId
      userId
      addr
    }
  }
`
