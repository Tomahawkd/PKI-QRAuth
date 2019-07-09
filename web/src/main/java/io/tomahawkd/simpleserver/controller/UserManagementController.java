package io.tomahawkd.simpleserver.controller;

import io.tomahawkd.pki.api.server.Token;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/user/management")
public class UserManagementController {

    @PostMapping("/log")
    public  String getUserLog(@RequestBody  String body, HttpServletRequest request)throws  Exception{
        return Token.getInstance().userLogManagement(body,request.getRemoteAddr(),request.getHeader("User-Agent"));
    }

    @PostMapping("/token/list")
    public  String getTokenList(@RequestBody  String body, HttpServletRequest request)throws  Exception{
        return Token.getInstance().tokenListManagement(body,request.getRemoteAddr(),request.getHeader("User-Agent"));
    }

    @PostMapping("/token/revoke")
    public String revokeTkoen(@RequestBody String body,HttpServletRequest request) throws  Exception{
        return  Token.getInstance().revokeToken(body,request.getRemoteAddr(),request.getHeader("User-Agent"));
    }

    @PostMapping("/regenkeys")
    public String regenerateKeys(@RequestBody String body,HttpServletRequest request)throws Exception{
        return  Token.getInstance().regenerateKeys(body, request.getRemoteAddr(),request.getHeader("User-Agent"));
    }

}
