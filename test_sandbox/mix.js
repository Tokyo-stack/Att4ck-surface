/**
 * JavaScript Vulnerabilities - JS mix.js
 */

// ================================================================
// 1. DOM XSS - innerHTML
// ================================================================

function displayUserInput(input) {
    document.getElementById('output').innerHTML = input;  // VULNERABLE: DOM XSS
}


function setOuterHTML(input) {
    element.outerHTML = input;  // VULNERABLE: DOM XSS
}


// ================================================================
// 2. DOM XSS - document.write
// ================================================================

function writeToPage(content) {
    document.write(content);  // VULNERABLE: DOM XSS
}


// ================================================================
// 3. DOM XSS - insertAdjacentHTML
// ================================================================

function insertHTML(element, html) {
    element.insertAdjacentHTML('afterbegin', html);  // VULNERABLE: DOM XSS
}


// ================================================================
// 4. Code Execution - eval
// ================================================================

function executeJS(code) {
    eval(code);  // VULNERABLE: eval execution
}


// ================================================================
// 5. Code Execution - Function Constructor
// ================================================================

function createFunction(code) {
    return new Function('return ' + code);  // VULNERABLE: Function constructor
}


// ================================================================
// 6. Code Execution - setTimeout
// ================================================================

function delayedExecute(input) {
    setTimeout("doSomething('" + input + "')", 1000);  // VULNERABLE: setTimeout with string
}


// ================================================================
// 7. Code Execution - setInterval
// ================================================================

function repeatedExecute(input) {
    setInterval("doSomething('" + input + "')", 1000);  // VULNERABLE: setInterval with string
}


// ================================================================
// 8. Hardcoded Secrets
// ================================================================

const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";  // VULNERABLE: Hardcoded
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";  // VULNERABLE: Hardcoded
const JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";  // VULNERABLE: Hardcoded


// ================================================================
// 9. Insecure HTTP
// ================================================================

fetch('http://insecure-api.example.com/data');  // VULNERABLE: HTTP not HTTPS


// ================================================================
// 10. Insecure WebSocket
// ================================================================

const ws = new WebSocket('ws://localhost:8080');  // VULNERABLE: ws:// not wss://


// ================================================================
// 11. Open Redirect
// ================================================================

function redirectUser(url) {
    window.location.href = url;  // VULNERABLE: Open redirect
}


// ================================================================
// 12. SSRF
// ================================================================

function fetchData(url) {
    fetch(url);  // VULNERABLE: SSRF - no validation
}


// ================================================================
// 13. Sensitive Data Logging
// ================================================================

function processUser(user) {
    console.log('User password:', user.password);  // VULNERABLE: Password in logs
    console.log('User token:', user.token);  // VULNERABLE: Token in logs
}


// ================================================================
// 14. React XSS - dangerouslySetInnerHTML
// ================================================================

const UserContent = () => {
    return <div dangerouslySetInnerHTML={{ __html: userInput }} />;  // VULNERABLE: React XSS
};


// ================================================================
// 15. Vue XSS - v-html
// ================================================================

// <span v-html="userContent"></span>  // VULNERABLE: Vue XSS


// ================================================================
// 16. SQL Injection (Client-side)
// ================================================================

function getUsers(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;  // VULNERABLE: SQL Injection
    db.execute(query);
}


// ================================================================
// 17. GraphQL Injection
// ================================================================

function getUserData(userId) {
    const query = gql`query { user(id: ${userId}) { name } }`;  // VULNERABLE: GraphQL Injection
}


// ================================================================
// 18. Cross-Site Scripting via javascript: URI
// ================================================================

function navigateTo(url) {
    window.location = 'javascript:' + url;  // VULNERABLE: javascript: URI
}