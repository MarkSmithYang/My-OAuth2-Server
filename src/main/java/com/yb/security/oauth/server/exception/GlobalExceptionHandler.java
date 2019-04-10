package com.yb.security.oauth.server.exception;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;


/**
 * author biaoyang
 * Date: 2019/4/8 0008
 * Description: 接口统一异常捕捉类
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ResponseStatus( HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ConstraintViolationException.class)
    public JSONObject constraintViolationExceptionHandler(ConstraintViolationException e) {
        log.error(e.getMessage(), e);
        final String message = e.getConstraintViolations()
                .stream()
                .map(ConstraintViolation::getMessage)
                .reduce((s, s2) -> s + ", " + s2)
                .orElse("");
        //封装数据
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", HttpStatus.BAD_REQUEST.value());
        jsonObject.put("message", message);
        return jsonObject;
    }

    @ResponseStatus( HttpStatus.BAD_REQUEST)
    @ExceptionHandler(RuntimeException.class)
    public JSONObject exceptionHandler(RuntimeException e) {
        log.error(e.getMessage(), e);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", HttpStatus.BAD_REQUEST.value());
        jsonObject.put("message", "网络异常");
        return jsonObject;
    }

    @ResponseStatus( HttpStatus.BAD_REQUEST)
    @ExceptionHandler(Exception.class)
    public JSONObject exceptionHandler(Exception e) {
        log.error(e.getMessage(), e);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", HttpStatus.BAD_REQUEST.value());
        jsonObject.put("message", "网络异常");
        return jsonObject;
    }

}
