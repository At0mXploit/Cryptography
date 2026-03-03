# Traditional Session ID Cookies:
# - After login, the server creates a session object stored on the backend.
# - The client (browser) receives a session ID cookie.
# - On each request, the browser automatically sends the cookie.
# - The server looks up the session using that ID and authorises the user.
# - Sessions live on the server.

# JWT-Based Sessions:
# - After login, the server sends a JWT containing the entire session data.
# - The JWT payload includes username, privileges, expiration, etc.
# - The token is signed with the server's secret key to prevent tampering.
# - The browser stores the JWT (usually in local storage).
# - On each request, the browser sends the JWT to the server.
# - The server verifies the signature, then reads the payload to authorise the user.
# - Sessions live on the client.

# Advantages of JWTs:
# - Easy to scale across multiple backend servers.
# - No need for shared session storage.
# - Any server can verify the token using the secret key.
# - Efficient for large systems with millions of users.

# Downsides:
# - Clients can read and modify tokens.
# - Misconfigured verification can lead to security vulnerabilities.
# - Sensitive data should not be stored in plaintext inside JWTs.

# HTTP header used to send JWTs:
# Authorization
#
# Typically formatted as:
# Authorization: Bearer <token>
#
# Flag:
# crypto{Authorization}
