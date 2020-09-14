import {gql} from "../utils/gql.js"

export const query = gql`
  mutation RequestOtp($phone: String) {
    requestOtp(phone: $phone) {
      token
      step
    }
  }
`
