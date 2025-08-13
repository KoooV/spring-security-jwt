package com.kov.springsecurityjwt.service;

import com.kov.springsecurityjwt.model.User;
import com.kov.springsecurityjwt.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;


    public User registerUser(String name, String password) {
        String hashedPassword = passwordEncoder.encode(password);
        User user = new User();
        user.setName(name);
        user.setPasswordHash(hashedPassword);
        return userRepository.save(user);
    }
    public User findByName(String name){
        return userRepository.findByName(name);

    }

}
