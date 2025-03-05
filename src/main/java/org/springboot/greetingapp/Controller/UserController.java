package org.springboot.greetingapp.Controller;


import org.springboot.greetingapp.Entities.Auth;
import org.springboot.greetingapp.Interfaces.IAuthInterface;
import org.springboot.greetingapp.Model.AuthUserDTO;
import org.springboot.greetingapp.Model.LoginUserDTO;
import org.springboot.greetingapp.Model.MailDTO;
import org.springboot.greetingapp.Services.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @Autowired
    EmailService emailService;

    IAuthInterface authInterface;



    // UC9 - For Registration of a User
    @PostMapping("/register")
    public String registerUser(@RequestBody AuthUserDTO user) {
        return authInterface.registerUser(user);
    }

    //UC10 - For User Login
    @PostMapping("/login")
    public String loginUser(@RequestBody LoginUserDTO user) {
        return authInterface.loginUser(user);
    }

    //UC11 - For Sending Mails to User
    @PostMapping("/sendMail")
    public String sendMail(@RequestBody MailDTO mail) {
        emailService.sendEmail(mail.getTo(),mail.getSubject(),mail.getMessage());
        return "Mail Sent Successfully";
    }

    //UC12 - Swagger Functionality Testing

}



