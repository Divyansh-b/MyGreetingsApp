package org.springboot.greetingapp.Interfaces;

import org.springboot.greetingapp.Model.Message;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public interface IGreetingInterface {
    public String getGreeting();
    public Message save(Message message);
    public Message findById(Long id);
    public List<Message> listAllMessages();
    public Message updateById(Message message, Long id);
    public String deleteMessage(Long id);
}
