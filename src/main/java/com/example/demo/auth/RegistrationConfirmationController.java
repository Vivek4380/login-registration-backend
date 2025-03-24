package com.example.demo.auth;

import com.example.demo.appuser.AppUserService;
import com.example.demo.registration.token.ConfirmationToken;
import com.example.demo.registration.token.ConfirmationTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/registration")
@CrossOrigin(origins = "*")
public class RegistrationConfirmationController {

    private final AppUserService appUserService;
    private final ConfirmationTokenService tokenService;

    public RegistrationConfirmationController(AppUserService appUserService, ConfirmationTokenService tokenService) {
        this.appUserService = appUserService;
        this.tokenService = tokenService;
    }

    @GetMapping("/confirm")
    public ResponseEntity<?> confirm(@RequestParam("token") String token) {
        ConfirmationToken confirmationToken = tokenService.getToken(token);
        if (confirmationToken == null) {
            return ResponseEntity.badRequest().body("Invalid token");
        }
        appUserService.enableAppUser(confirmationToken.getAppUser().getEmail());
        return ResponseEntity.ok("Account confirmed successfully!");
    }
}