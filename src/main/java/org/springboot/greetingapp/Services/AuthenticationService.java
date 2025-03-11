package org.springboot.greetingapp.Services;

import org.springboot.greetingapp.Entities.Auth;
import org.springboot.greetingapp.Interfaces.IAuthInterface;
import org.springboot.greetingapp.Model.AuthUserDTO;
import org.springboot.greetingapp.Model.LoginUserDTO;
import org.springboot.greetingapp.Model.PathDTO;
import org.springboot.greetingapp.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service

public class  AuthenticationService implements IAuthInterface {
    @Autowired
 UserRepository userRepository;
    @Autowired
EmailService emailService;
    @Autowired
JWTServiceToken jwtServiceToken;

    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
public String registerUser(AuthUserDTO user){
    List<Auth> list1 = userRepository.findAll().stream().filter(u -> u.getEmail().equals(user.getEmail())).collect(java.util.stream.Collectors.toList());
    if(list1.size()>0){
        return "Email Already Exists";
    }
    // Creating Hash Password Using Bycrypt

    String hassPass = bCryptPasswordEncoder.encode(user.getPassword());

    // Creating New User
    Auth newUser = new Auth(user.getFirstName(),user.getLastName(),user.getEmail(), user.getPassword(), hassPass);

    // Setting the new Hashed Password

    newUser.setHashedPassword(hassPass);
    userRepository.save(newUser);
    emailService.sendEmail(newUser.getEmail(),"Welcome to Greeting App",user.getFirstName()+" Welcome to Greeting App");
    return "User Registered Successfully";



}
public String loginUser(LoginUserDTO user){
    List<Auth> list1 = userRepository.findAll().stream().filter(u -> u.getEmail().equals(user.getEmail())).collect(java.util.stream.Collectors.toList());
    if(list1.size()==0) return "User not Registered";

    Auth found = list1.get(0);


    if(!bCryptPasswordEncoder.matches(user.getPassword(),found.getHashedPassword())) return "Invalid Password";

    String token = jwtServiceToken.createToken(found.getUserID());

    found.setToken(token);
    userRepository.save(found);
    emailService.sendEmail(found.getEmail(), "Login User","User Logged In !");
    return "User Logged In Successfully"+token;
}

public AuthUserDTO forgotPassword(PathDTO passDTO) {
    Auth found = userRepository.findByEmail(passDTO.getEmail());
    if (found == null) throw new RuntimeException("User Not Found");

    if (passDTO.getNewPassword() == null || passDTO.getNewPassword().isEmpty()) {
        throw new IllegalArgumentException("New password cannot be null or empty");
    }


    String hashedPass = bCryptPasswordEncoder.encode(passDTO.getNewPassword());

    found.setPassword(hashedPass);  // Store the hashed password
    userRepository.save(found);

    AuthUserDTO authUserDTO = new AuthUserDTO(found.getFirstName(), found.getLastName(), found.getEmail(), found.getPassword(), found.getUserID());
    emailService.sendEmail(found.getEmail(), "Password Changed", "Password Changed");
    return authUserDTO;
}
public String resetPassword(String email,String curePassword, String newPassword) {
    Auth found = userRepository.findByEmail(email);
    if (found == null) throw new RuntimeException("User Not Found");

    if(!bCryptPasswordEncoder.matches(curePassword,found.getHashedPassword())){
        throw new IllegalArgumentException("New password does not match");
    }
    found.setHashedPassword(newPassword);
    found.setPassword(bCryptPasswordEncoder.encode(newPassword));
    userRepository.save(found);
    emailService.sendEmail(email, "Password Reset", "Password Reset Successfully");
    return "Password Reset Successfully";
}


}


