package com.authentication.auth.features.user.entities;

public enum Role {
    USER,
    ADMIN,
    NOT_SET;

    /*public static Role convertStringToRole(String role) {
        if (role.equalsIgnoreCase("user")) {
            return Role.USER;
        } else if (role.equalsIgnoreCase("admin")) {
            return Role.ADMIN;
        } else {
            return Role.NOT_SET;
        }
    }*/

    public static Role convertStringToRole(String role) {
        return switch (role.toLowerCase()) {
            case "user" -> Role.USER;
            case "admin" -> Role.ADMIN;
            default -> Role.NOT_SET;
        };
    }
}
