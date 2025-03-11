package org.springboot.greetingapp.Interfaces;

import org.springboot.greetingapp.Model.AuthUserDTO;
import org.springboot.greetingapp.Model.LoginUserDTO;
import org.springboot.greetingapp.Model.PathDTO;
import org.springframework.stereotype.Service;

@Service
public interface IAuthInterface {
    public String registerUser(AuthUserDTO user);
    public String loginUser(LoginUserDTO user);
    public AuthUserDTO forgotPassword(PathDTO pass);
}
