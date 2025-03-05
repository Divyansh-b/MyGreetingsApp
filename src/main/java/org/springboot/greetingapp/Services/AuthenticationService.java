package org.springboot.greetingapp.Services;

import org.springboot.greetingapp.Entities.Auth;
import org.springboot.greetingapp.Model.AuthUserDTO;
import org.springboot.greetingapp.Repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service

public class AuthenticationService {
UserRepository userRepository;
EmailService emailService;
public AuthenticationService(UserRepository userRepository, EmailService emailService) {
    this.userRepository = userRepository;
    this.emailService = emailService;
}
public String register(AuthUserDTO user){
    List<Auth> list1 = userRepository.findAll().stream().filter(u -> u.getEmail().equals(user.getEmail())).collect(java.util.stream.Collectors.toList());
    if(list1.size()>0){
        return "Email Already Exists";
    }
    // Creating Hash Password Using Bycrypt
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    String hassPass = encoder.encode(user.getPassword());

    // Creating New User
    Auth newUser = new Auth(user.getFirstName(),user.getLastName(),user.getEmail(), user.getPassword(), hassPass);

    // Setting the new Hashed Password

    newUser.setHashedPassword(hassPass);
    userRepository.save(newUser);
    emailService.sendEmail(newUser.getEmail(),"Welcome to Greeting App",user.getFirstName()+" Welcome to Greeting App");
    return "User Registered Successfully";



}

}
