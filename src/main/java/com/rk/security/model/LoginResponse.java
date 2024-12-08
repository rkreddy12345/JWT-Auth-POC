package com.rk.security.model;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class LoginResponse {
    private String token;
    private String username;
    private List <String> roles;
}
