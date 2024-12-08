package com.rk.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class WishController {

    @PreAuthorize ( "hasRole('ADMIN')" )
    @GetMapping(("/admin/hello"))
    public String sayHelloToAdmin() {
        return "Hello admin";
    }

    @PreAuthorize ( "hasRole('USER')" )
    @GetMapping(("/user/hello"))
    public String sayHelloToUser() {
        return "Hello user";
    }
}
