package com.auth.authserverjwt.converters;

import com.auth.authserverjwt.dto.UserResponse;
import com.auth.authserverjwt.entities.User;

import java.util.ArrayList;
import java.util.List;

public abstract class UserConverter {

    private UserConverter() {}

    public static UserResponse userToUserResponse(User user) {
        UserResponse userResponse = new UserResponse();
        userResponse.setId(user.getId());
        userResponse.setAuthority(user.getAuthority());
        userResponse.setEmail(user.getEmail());
        userResponse.setAccountNonLocked(user.isAccountNonLocked());
        userResponse.setEnabled(user.isEnabled());
        userResponse.setCreatedAt(user.getCreatedAt());
        userResponse.setUpdatedAt(user.getUpdatedAt());
        return userResponse;
    }

    public static List<UserResponse> usersToUserResponses(List<User> users) {
        List<UserResponse> userResponses = new ArrayList<>();
        for (User user : users) {
            userResponses.add(userToUserResponse(user));
        }
        return userResponses;
    }
}
