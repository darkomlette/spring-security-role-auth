package com.javatechie.group.controller;

import com.javatechie.group.common.UserConstant;
import com.javatechie.group.config.KafkaProducer;
import com.javatechie.group.entity.User;
import com.javatechie.group.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository repository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    KafkaProducer kafkaProducer;

    @PostMapping("/createUser")
    public String joinGroup(@RequestBody User user) {
        user.setRoles(UserConstant.DEFAULT_ROLE);//USER
        String encryptedPwd = passwordEncoder.encode(user.getPassword());
        user.setPassword(encryptedPwd);
        repository.save(user);
        kafkaProducer.sendMessage("Log entry || User Created || "+user.getUserName());
        return "Hi " + user.getUserName() + " welcome to group !";
    }
    //If loggedin user is ADMIN -> ADMIN OR MODERATOR
    //If loggedin user is MODERATOR -> MODERATOR

    @GetMapping("/access/{userId}/{userRole}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR')")
    public String giveAccessToUser(@PathVariable int userId, @PathVariable String userRole, Principal principal) {
        User user = repository.findById(userId).get();
        List<String> activeRoles = getRolesByLoggedInUser(principal);
        String newRole = "";
        if (activeRoles.contains(userRole)) {
            newRole = user.getRoles() + "," + userRole;
            user.setRoles(newRole);
        }
        repository.save(user);
        kafkaProducer.sendMessage("Log entry || User Roles Modified || TO "+user.getUserName()+" By "+ principal.getName());
        return "Hi " + user.getUserName() + " New Role assign to you by " + principal.getName();
    }

    @GetMapping("/getUserList")
    @Secured("ROLE_ADMIN")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> loadUsers() {

        return repository.findAll();
    }

    @GetMapping("/getDetails/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR') or hasAuthority('ROLE_USER')")
    public ResponseEntity<?> fetchUserDetails(@PathVariable int userId, Principal principal) {
        User user = repository.findByUserName(principal.getName()).get();
        List<String> currentRoles = Arrays.stream(user.getRoles().split(",")).collect(Collectors.toList());
        if (userId != user.getId()) {
            if ((currentRoles.contains("ROLE_ADMIN") || currentRoles.contains("ROLE_MODERATOR"))) {
                User requiredUser = repository.findById(userId).get();
                kafkaProducer.sendMessage("Log entry || User Details Fetch || For "+requiredUser.getUserName()+
                        " By "+ principal.getName());
                return ResponseEntity.ok(requiredUser);
            } else {
                return ResponseEntity.badRequest().body("You don't have permission to view other user data");
            }
        }
        return ResponseEntity.ok(user);
    }

    @PostMapping("/updateDetails/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR') or hasAuthority('ROLE_USER')")
    public ResponseEntity<?> updateUserDetails(@RequestBody User userObject, @PathVariable int userId, Principal principal) {
        User user = repository.findByUserName(principal.getName()).get();
        List<String> currentRoles = Arrays.stream(user.getRoles().split(",")).collect(Collectors.toList());
        if (userId != user.getId()) {
            if ((currentRoles.contains("ROLE_ADMIN") || currentRoles.contains("ROLE_MODERATOR"))) {
                user.setUserName(userObject.getUserName());
                user.setActive(userObject.isActive());
                repository.save(user);
                kafkaProducer.sendMessage("Log entry || User Details Updated || For "+user.getUserName()+
                        " By "+ principal.getName());
                return ResponseEntity.ok("Details updated for {" + userId + "} by " + principal.getName());
            } else {
                return ResponseEntity.badRequest().body("You don't have permission to update other user data");
            }
        } else {
            user.setUserName(userObject.getUserName());
            user.setActive(userObject.isActive());
            repository.save(user);
            kafkaProducer.sendMessage("Log entry || User Details Fetch || For "+user.getUserName()+
                    " By "+ user.getUserName());
            return ResponseEntity.ok("Details updated for " + userId + " by " + principal.getName());
        }
    }

    @PostMapping("/deleteUser/{userId}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_USER','ROLE_MODERATOR')")
    public ResponseEntity<?> deleteUser(@PathVariable int userId, Principal principal) {
        User user = repository.findById(userId).get();
        List<String> currentRoles = Arrays.stream(user.getRoles().split(",")).collect(Collectors.toList());
        if ((currentRoles.contains("ROLE_ADMIN") || currentRoles.contains("ROLE_MODERATOR"))) {
            kafkaProducer.sendMessage("Log entry || User Profile Deleted || For "+user.getUserName()+
                    " By "+ principal.getName());
            repository.delete(user);
            return ResponseEntity.ok("User details " + userId + " deleted by " + principal.getName());
        } else {
            return ResponseEntity.badRequest().body("You don't have permission to delete other user profile");
        }
    }

    private List<String> getRolesByLoggedInUser(Principal principal) {
        String roles = getLoggedInUser(principal).getRoles();
        List<String> assignRoles = Arrays.stream(roles.split(",")).collect(Collectors.toList());
        if (assignRoles.contains("ROLE_ADMIN")) {
            return Arrays.stream(UserConstant.ADMIN_ACCESS).collect(Collectors.toList());
        }
        if (assignRoles.contains("ROLE_MODERATOR")) {
            return Arrays.stream(UserConstant.MODERATOR_ACCESS).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private User getLoggedInUser(Principal principal) {
        return repository.findByUserName(principal.getName()).get();
    }


}
