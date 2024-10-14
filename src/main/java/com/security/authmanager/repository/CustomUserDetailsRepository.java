package com.security.authmanager.repository;

import com.security.authmanager.common.QueryConstants;
import com.security.authmanager.model.ERole;
import com.security.authmanager.model.Role;
import com.security.authmanager.model.User;
import com.security.authmanager.security.jwt.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Repository
public class CustomUserDetailsRepository {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsRepository.class);
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public User fetchUserByUserName(String userName){
        try{
            return jdbcTemplate.query((conn) ->{
                final PreparedStatement ps = conn.prepareStatement(QueryConstants.FETCH_USER);
                ps.setString(1, userName.toUpperCase());
                return ps;
            },rs->{
                User user = null;
                Set<Role> roles = new HashSet<>();
                while (rs.next()) {
                    if (user == null) {
                        user = new User();
                        user.setEmail(rs.getString("email"));
                        user.setId(rs.getLong("uniqueid"));
                        user.setPassword(rs.getString("password"));
                        user.setUsername(rs.getString("username"));
                    }
                    Role role = new Role();
                    role.setId(rs.getInt("id"));
                    role.setName(ERole.valueOf(rs.getString("name")));
                    roles.add(role);
                }
                if (user != null) {
                    user.setRoles(roles);
                }
                return user;
            });
        }catch(Exception e){
            logger.error("Exception in fetchUserByUserName()",e);
            throw new RuntimeException(e);
        }
    }

    public boolean existsByUsername(String userName) {
        try{
              return jdbcTemplate.query((conn) -> {
                 final PreparedStatement ps = conn.prepareStatement(QueryConstants.CHECK_USER_BY_USERNAME);
                 ps.setString(1, userName.toUpperCase());
                 return ps;
             }, (rs,rownum) -> rs.getInt("count")).get(0)>0;
        }catch(Exception e){
            logger.error("Exception in existsByUsername()",e);
            throw new RuntimeException(e);
        }
    }

    public boolean existsByEmail(String email) {
        try{
            return jdbcTemplate.query((conn) -> {
                final PreparedStatement ps = conn.prepareStatement(QueryConstants.CHECK_USER_BY_EMAIL);
                ps.setString(1, email.toUpperCase());
                return ps;
            }, (rs,rownum) -> rs.getInt("count")).get(0)>0;
        }catch(Exception e){
            logger.error("Exception in existsByEmail()",e);
            throw new RuntimeException(e);
        }
    }

    public Role findRoleByName(ERole eRole) {
        try{
            return jdbcTemplate.query((conn) -> {
                final PreparedStatement ps = conn.prepareStatement(QueryConstants.FETCH_ROLE_BY_NAME);
                ps.setString(1, String.valueOf(eRole));
                return ps;
            }, rs -> {
                Role role=null;
                while(rs.next()){
                    role = new Role();
                    role.setName(ERole.valueOf(rs.getString("name")));
                    role.setId(rs.getInt("id"));
                }
                return role;
            });
        }catch(Exception e){
            logger.error("Exception in findRoleByName()",e);
            throw new RuntimeException(e);
        }
    }

    public void createUser(User user) {
        try(Connection conn = Objects.requireNonNull(jdbcTemplate.getDataSource()).getConnection()){
            try (PreparedStatement userStatement = conn.prepareStatement(QueryConstants.INSERT_TO_USERS,Statement.RETURN_GENERATED_KEYS)) {
                userStatement.setString(1, user.getEmail().toUpperCase());
                userStatement.setString(2, user.getPassword());
                userStatement.setString(3, user.getUsername().toUpperCase());

                userStatement.executeUpdate();

                // Retrieve generated userId
                try (ResultSet generatedKeys = userStatement.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        Long userId = generatedKeys.getLong(1); // Assuming userId is of type VARCHAR
                        logger.info("gen userid {}",userId.toString());
                        user.setId(userId);
                    }
                }
            }
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                try (PreparedStatement userRoleStatement = conn.prepareStatement(QueryConstants.INSERT_TO_USER_ROLES)) {
                    for (Role role : user.getRoles()) {
                        userRoleStatement.setLong(1, user.getId());
                        userRoleStatement.setLong(2, role.getId());
                        userRoleStatement.executeUpdate();
                    }
                }
            }
        }catch(Exception e){
            logger.error("Exception in existsByEmail()",e);
            throw new RuntimeException(e);
        }

    }
}
