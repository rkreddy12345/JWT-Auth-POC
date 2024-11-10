package com.rk.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WishController {
    @GetMapping(("/hello"))
    public String sayHello() {
        return "Hello";
    }
}
