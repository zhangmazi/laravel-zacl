<?php
/**
 * ALC配置
 * author:ninja911
 * email:ninja911#qq.com
 * date:2015-05-06 15:08
 */
return array(
    'AUTH_COOFIKE_PREFIX' => 'auth_cookie_',   //Cookie前缀
    'AUTH_LOGIN_URL' => '/login',   //登陆地址
    'AUTH_LOGIN_NO' =>  array('Signin' => array('index', 'publish', 'unlock', 'logout', 'captcha'),
        'Manager' => array('info', 'publish')),  //免验证控制器
    'AUTH_SESSION_PREFIX' => 'auth_session_',   //会话前缀
    'AUTH_POWER_CACHE' => true, //是否缓存权限
    //不录入表的方法
    'AUTH_FILTER_METHOD' => array('beforeFilter', 'afterFilter', 'forgetBeforeFilter', 'forgetAfterFilter',
        'getBeforeFilters', 'getAfterFilters', 'getFilterer', 'setFilterer', 'callAction', 'missingMethod',
        'getMiddleware', 'middleware', 'getRouter', 'setRouter', 'validate', 'validateWithBag'),
    'AUTH_TABLE' => array(
        'role' => array(
            'name' => 'manager_role',
            'field' => array(
                'id' => 'role_id',
                'pid' => 'parent_id',
                'name' => 'role_name',
                'power' => 'power_value',
                'squad' => 'squad',
            ),
        ),
        'resource' => array(
            'name' => 'manager_resource',
            'field' => array(
                'id' => 'resource_id',
                'pid' => 'parent_id',
                'name' => 'resource_name',
                'operate' => 'operate',
                'squad' => 'squad',
            ),
            ''
        ),
    ),
);
