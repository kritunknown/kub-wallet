import {gql} from "../utils/gql.js"

export const query = gql`
  mutation AuthenticateOtp($phone: String, $otp: String, $token: String) {
    authenticateOtp(phone: $phone, otp: $otp, token: $token) {
      token
      step
      sessionId
    }
  }
`
