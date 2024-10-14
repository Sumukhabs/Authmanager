package com.security.authmanager.repository;

import com.security.authmanager.common.QueryConstants;
import com.security.authmanager.model.ERole;
import com.security.authmanager.model.RefreshToken;
import com.security.authmanager.model.Role;
import com.security.authmanager.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Optional;

@Repository
public class RefreshTokenRepository {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenRepository.class);
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public void deleteRefreshToken(RefreshToken refreshToken) {
        try{
            jdbcTemplate.update(QueryConstants.DELETE_REFRESH_TOKEN,(final PreparedStatement ps) ->{
                ps.setString(1,refreshToken.getToken());
            });
        }catch (Exception e){
            logger.error("Exception in deleteRefreshToken()",e);
            throw new RuntimeException(e);
        }
    }

    public int deleteRefreshTokenByUser(User user) {
        return 0;
    }

    public RefreshToken saveRefreshToken(RefreshToken refreshToken) {
        try{
            jdbcTemplate.update(QueryConstants.SAVE_REFRESH_TOKEN,(final PreparedStatement ps) ->{
                ps.setLong(1,refreshToken.getUser().getId());
                ps.setString(2,refreshToken.getToken());
                ps.setTimestamp(3, Timestamp.from(refreshToken.getExpiryDate()));
            });
        }catch (Exception e){
            logger.error("Exception in saveRefreshToken()",e);
            throw new RuntimeException(e);
        }
        return refreshToken;
    }

    public Optional<RefreshToken> findByToken(String token) {
        RefreshToken refreshToken = new RefreshToken();
        try{
            return Optional.ofNullable(jdbcTemplate.query((conn) -> {
                final PreparedStatement ps = conn.prepareStatement(QueryConstants.FIND_BY_TOKEN);
                ps.setString(1, token);
                return ps;
            }, rs -> {
                User user = new User();
                while (rs.next()) {
                    refreshToken.setId(rs.getLong("id"));
                    refreshToken.setToken(rs.getString("token"));
                    refreshToken.setExpiryDate(rs.getTimestamp("expiryDate").toInstant());
                    user.setId(rs.getLong("uniqueid"));
                    user.setEmail(rs.getString("email"));
                    user.setUsername(rs.getString("username"));
                    refreshToken.setUser(user);
                }
                return refreshToken;
            }));
        }catch(Exception e){
            logger.error("Exception in findByToken()",e);
            throw new RuntimeException(e);
        }
    }
}
