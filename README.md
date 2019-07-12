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
          | -- app
                | -- build
                | -- libs
                       | -- clientAPI.jar
                | --  src (source code)
                       | -- main
                              | -- assets
                                     | -- URLconfig (store server address)
                              | -- java
                                     | -- com.Vshows.PKI
                                             | -- fragment
                                                   | -- userInfoFragment 
                                                   | -- userLogFragment 
                                             | -- util
                                                   | -- DBHelper (create SQLite)
                                                   | -- keyManager (database operation)
                                                   | -- StringToKey 
                                                   | -- SystemUtil (get device infomation)
                                                   | -- TokenList
                                                   | -- TokenListAdapter (show token list ListView)
                                                   | -- URLUtil (get url from URLConfig)
                                                   | -- UserLog
                                                   | -- UserLogAdapter (show user log ListView)
                                             | -- BottomBar
                                             | -- changepsw
                                             | -- ChangeSelfInfo
                                             | -- ChangeToken
                                             | -- Check (confirm login)
                                             | -- index
                                             | -- Login 
                                             | -- Register 
                                             | -- Scan 
                                             | -- welcome
                              | -- res
                                     | -- drawable
                                     | -- layout (xml dir)
                                     | -- mipmap-anydpi-v26
                                     | -- mipmap-hdpi
                                     | -- mipmap-mdpi
                                     | -- mipmap-xhdpi
                                     | -- mipmap-xxhdpi
                                     | -- mipmap-xxxhdpi
                                     | -- values
                              | -- AndriodManifest.xml
                | -- .gitignore
                | -- app.iml
                | -- build.gradle
                | -- proguard-rules.pro
                | -- zxing.jks
          | -- gradle
          | -- zxinglibrary (library for scanning QRcode)
          | -- .gitignore
          | -- build.gradle
          | -- gradle.properties
          | -- gradlew
          | -- gradlew.bat
          | -- local.properties
          | -- OWENERS
          | -- README.md
          | -- settings.gradle
                                     
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
