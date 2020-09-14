import {gql} from "../utils/gql.js"

export const query = gql`
  query Me($sessionId: ID) {
    me(sessionId: $sessionId) {
      userId
      addr
      vsn
      phone
      name
      avatar
      cover
      color
      bio
    }
  }
`
