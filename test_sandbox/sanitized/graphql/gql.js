const { gql } = require("@apollo/client");
const QUERY = gql`query($id: ID!) { user(id: $id) { name } }`;
function q(client, id) { return client.query({ query: QUERY, variables: { id } }); }
