package io.tomahawkd.simpleserver.controller;

import io.tomahawkd.pki.api.server.Token;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/server/qr")
public class QrController {

    @PostMapping("/gener")
    public String qrGeneration(@RequestBody String body, HttpServletRequest request) throws Exception {
        return Token.getInstance().qrgenerate(body,request);
    }

    @PostMapping("/opera")
    public String qrOperation(@RequestBody String body,HttpServletRequest request) throws Exception {
        return Token.getInstance().qroperation(body,request);
    }

    @PostMapping("/roll")
    public String qrRolling(@RequestBody String body,HttpServletRequest request) throws Exception {
        return Token.getInstance().rolling(body,request);
    }
}
