# Oauth2 and OpenID 
Oauth2 and OpenID is an example usage of goguardian oauth2 package. the example provides a simple REST API for a login using google oauth2 and an api to query a book author by id.

# Getting Started
1. [https://www.balbooa.com/gridbox-documentation/how-to-get-google-client-id-and-client-secret](create google oauth2 client id and secret)
2. run example 
```sh
CLIENT_ID="" CLIENT_SECRET="" go run main.go 
```
3. open web browser and hit http://127.0.0.1:8080/v1/auth/login.
4. login using your google.
5. copy the token
6. http://127.0.0.1:8080/v1/book/1449311601?token=<paste token>

**Note:** you may encounter `strategies/oauth2/jwt: claims: standard claims issued at a future time` so wait a few seconds until token activated.
