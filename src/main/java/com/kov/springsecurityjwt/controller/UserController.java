package com.kov.springsecurityjwt.controller;

import com.kov.springsecurityjwt.Dto.RegisterRequestDto;
import com.kov.springsecurityjwt.model.User;
import com.kov.springsecurityjwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/users/")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    public User register(@RequestBody RegisterRequestDto registerRequestDto) {
        return userService.registerUser(registerRequestDto.getUsername(), registerRequestDto.getPassword());
    }

}
