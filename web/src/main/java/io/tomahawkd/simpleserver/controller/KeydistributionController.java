package io.tomahawkd.simpleserver.controller;

import io.tomahawkd.pki.api.server.Token;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;


@RestController
@RequestMapping("/key/dist")
public class KeydistributionController {



    @GetMapping("/tpub")
    public String getTPubkeys()throws Exception{
        return  Token.getInstance().TPublicKeyDistribute();
    }
    @GetMapping("/spub")
    public String getSPubKeys() throws  Exception{
        return Token.getInstance().SpublicKeyDistribute();
    }


}
