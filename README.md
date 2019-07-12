# PKI-QRAuth
PKI based QR code authentication system

## Project Structure
```
   / -- web (for web service)
          | -- src (source code)
                | -- main
                       | -- java
                              | -- io/tomahawkd/pki
                                        | -- controller (backend request interface)
                                        | -- dao (database interface)
                                        | -- model (database model)
                                        | -- service
                                        | -- PkiApplication.java (Startup class)
                       | -- resources
                              | -- static (js/css dir)
                              | -- templates (html dir)
                              | -- application.properties (springboot configuration， ignored in github)
                | -- test
          | -- pom.xml (dependency)
          | -- README.md (Directory explanation)
          | -- .gitignore
          | -- OWNERS (Directory permission controll)
   | -- pkiservice (third party key/token distribution and management)
   | -- pki-client-api (client api part for pkiservice)
   | -- pki-server-api (server api part for pkiservice)
   | -- pki-api-common (common class in client and server)
   | -- android (for android client)
          | --  
```
## Permission
This project is divided into several permissions:

- Management: @Tomahawkd
- Write: Depends on directory
- Read: Everyone

## Project Member
@Tomahawkd, @Vshows, @Dracula1998, @zhangxu1814, @czzzzz0, @QhY1QHY

### Contribution

1. Fork the project

2. Contribute code

3. **Check repo update and merge into your code**

4. pull request

### Note

1. With the summer internship ends, the repo will hardly be updated. And I will maintain the repo from time to time when I get free.

2. Considering the effeciency of the authentication server, I would transfer to use TCP protocol by project [netty](https://github.com/netty/netty) for smaller transfering bytes and higher performance.
