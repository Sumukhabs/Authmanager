package com.security.authmanager.common;

public class QueryConstants {

    public static final String FETCH_USER = "SELECT u.uniqueid, u.username, u.email, u.password, r.id, r.name FROM ib.users u LEFT JOIN ib.user_roles ur ON u.uniqueid = ur.user_uniqueid LEFT JOIN ib.roles r ON ur.role_id = r.id WHERE UPPER(u.username) = ?";
    public static final String CHECK_USER_BY_USERNAME = "SELECT count(*) as count from ib.users where upper(username)=?";
    public static final String CHECK_USER_BY_EMAIL = "SELECT count(*) as count from ib.users where upper(email)=?";
    public static final String FETCH_ROLE_BY_NAME = "SELECT id,name from ib.roles where UPPER(name)=?";
    public static final String INSERT_TO_USERS = "INSERT INTO ib.users (email,password,username) values (?,?,?)";
    public static final String INSERT_TO_USER_ROLES = "INSERT INTO ib.user_roles (user_uniqueid,role_id) VALUES (?,?)";
    public static final String SAVE_REFRESH_TOKEN = "INSERT INTO ib.refresh_tokens (uniqueid, token, expiryDate) VALUES (?, ?, ?)";
    public static final String DELETE_REFRESH_TOKEN = "DELETE FROM ib.refresh_tokens WHERE token = ?";
    public static final String FIND_BY_TOKEN = "SELECT rt.id,rt.token,rt.expiryDate,us.uniqueid,us.email,us.username from ib.refresh_tokens rt inner join ib.users us on rt.uniqueid=us.uniqueid where rt.token=?";
}
