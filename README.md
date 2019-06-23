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
   | -- android (for android client)
          | -- app
                | -- build
                | -- release
                | --  src (source code)
                       | -- main
                              | -- java
                                     | -- com.Vshows.PKI
                                             | -- Check (confirm login)
                                             | -- Login 
                                             | -- Register 
                                             | -- Scan 
                              | -- res
                                     | -- drawable
                                     | -- layout
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
          | -- img
          | -- zxinglibrary (library for scanning QRcode)
          | -- .gitignore
          | -- build.properties
          | -- gradlew
          | -- gradlew.bat
          | -- local.properties
          | -- PKI_SCAN.iml
          | -- README.md
          | -- settings.gradle
          | -- sh.exe.stackdump
                                     
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
