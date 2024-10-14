package com.security.authmanager.controller;

import com.security.authmanager.exception.TokenRefreshException;
import com.security.authmanager.model.ERole;
import com.security.authmanager.model.RefreshToken;
import com.security.authmanager.model.Role;
import com.security.authmanager.model.User;
import com.security.authmanager.payloads.request.LoginRequest;
import com.security.authmanager.payloads.request.SignupRequest;
import com.security.authmanager.payloads.request.TokenRefreshRequest;
import com.security.authmanager.payloads.response.JwtResponse;
import com.security.authmanager.payloads.response.MessageResponse;
import com.security.authmanager.payloads.response.TokenRefreshResponse;
import com.security.authmanager.repository.CustomUserDetailsRepository;
import com.security.authmanager.security.jwt.JwtUtils;
import com.security.authmanager.security.service.RefreshTokenService;
import com.security.authmanager.security.service.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1.0/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    CustomUserDetailsRepository userRepository;

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getUsername());

        return ResponseEntity.ok(new JwtResponse(jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername().toLowerCase(),
                signUpRequest.getEmail().toUpperCase(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = userRepository.findRoleByName(ERole.ROLE_USER);
            if(userRole==null) {
                throw new RuntimeException("Error: Role not found.");
            }else {
                roles.add(userRole);
            }
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = userRepository.findRoleByName(ERole.ROLE_ADMIN);
                        if(adminRole==null) {
                            throw new RuntimeException("Error: Role not found.");
                        }
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = userRepository.findRoleByName(ERole.ROLE_MODERATOR);
                        if(modRole==null) {
                            throw new RuntimeException("Error: Role not found.");
                        }
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = userRepository.findRoleByName(ERole.ROLE_USER);
                        if(userRole==null) {
                            throw new RuntimeException("Error: Role not found.");
                        }
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.createUser(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}

