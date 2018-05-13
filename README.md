# rest-security-jwt
## A JWT based authentication and authorization boilerplate, using spring framework, to secure restful API
* use /login as authentication entry
* use spring security default setting for user authtication (username and password)
* add a **successHandler** to generate JWT token after successful authentication
* add a **customer filter** to check if JWT is in header and valid
* connect mysql database to look for user and password
* use BCryptPasswordEncoder to encrypt password before save to database
![Image of JWT flow](https://cdn.auth0.com/content/jwt/jwt-diagram.png)
