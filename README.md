# nulls-auth
Simple nulls plugin for authentification

# Features
* Verification codes
* OTP setup
* Password hashing
* Automatic users DB
* Stateless JWT sessions
* Whitelisting
* 2 step account reset from outside
* Password and OTP change from inside

# Super Secure
## Data Privacy Maxed Out
Database uses HMAC hashes for usernames.
In case your database is breached,
no information leaks to the outside.

## IP Fingerprint Validation And Expiration Policy
JWT sessions include an IP based fingerprint.
A newly issued cookie expires after 20 days.
In case a hacker obtains a valid JWT cookie,
it is hard (but not impossible) to abuse it,
since it is tied to an IP address.
The validation works by allowing the JWT to be
used from up to 3 different IP addresses in a
fixed time frame. If a new IP address is
detected more than 2 hours after the last IP
was saved, the token is considered invalid.
This is a good compromise between security
and usability.

There are two major cases to consider:
* The user visits the website from a stationary computer:
  * The user obtains the cookie for the current IP
  * The IP is unlikely to change
  * If the key is leaked more than 2 hours
    after the login, it can't be used by a hacker
    since their IP will be different
* The user visits the website from a mobile device:
  * Mobile devices are less likely to be infected with malware,
    thus reducing the chances of the cookie being stolen
  * If the IP of the user changes (for example during switching
    cellular networks) within 2 hours after the login,
    a new cookie is issued with an updated fingerprint
  * If the IP changes more than 2 hours after the login,
    it is likely, that the user is currently moving
    and is probably not going to visit the website shortly after

## JWT Triple Security
The JWT cookie which is used for session
management has been made very secure.
* JWT uses a secret key for signature validation:
  A hacker can not forge a valid JWT cookie
* The username is encrypted:
  In case a hacker obtains a valid JWT cookie,
  they won't be able to derive the username
* Encryption with AES-256-GCM: even if the secret key
  for the JWT cookies is leaked, the usernames still
  can't be generated
* The fingerprint is hashed, meaning the IP
  adresses of the user aren't exposed even
  if the cookie gets compromised
