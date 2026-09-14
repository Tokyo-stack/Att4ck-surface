const { gql } = require("@apollo/client");
function q(id) {
  return gql`query { user(id: "${id}") { name } }`;
}
