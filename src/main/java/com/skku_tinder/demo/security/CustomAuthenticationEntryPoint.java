package com.skku_tinder.demo.security;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String exception = (String)request.getAttribute("exception");
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        JSONObject responseJson = new JSONObject();
        try {
            responseJson.put("message", exception);
            responseJson.put("code", 500);
            response.getWriter().print(responseJson);
        } catch (JSONException e) {
            e.printStackTrace();
        }

    }
}
