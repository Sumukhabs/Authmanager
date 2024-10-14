package com.security.authmanager.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

@Configuration
public class DatabaseConfig {

    private final Environment env;

    public DatabaseConfig(Environment env) {
        this.env = env;
    }

    @Bean
    public DataSource dataSource() {
        HikariConfig dataSource = new HikariConfig();
        dataSource.setDriverClassName(env.getProperty("database.driverClassName"));
        dataSource.setPoolName(env.getProperty("database.poolName"));
        dataSource.setJdbcUrl(env.getProperty("database.jdbcUrl"));
        dataSource.setUsername(env.getProperty("database.username"));
        dataSource.setPassword(env.getProperty("database.password"));
        dataSource.setMaxLifetime(0);
        dataSource.setConnectionTimeout(500);
        dataSource.setMaximumPoolSize(env.getProperty("database.maxActive",Integer.class));
        dataSource.setMinimumIdle(env.getProperty("database.minIdle",Integer.class));
        return new HikariDataSource(dataSource);
    }
}
