package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.service.SystemLogService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class MainController {
    @Resource
    private SystemLogService service;

    @GetMapping("/")
    public String hello() {

        service.insertLogRecord("b","add",SystemLogModel.INFO,"fjdhf");

        return "hello";
    }
}
