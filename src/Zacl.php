<?php
/**
 * 访问控制
 * author:ninja911
 * email:ninja911#qq.com
 * date:2015-05-06 15:12
 */
namespace Zhangmazi\Zacl;

use Illuminate\Support\Facades\Session as Session;
use Carbon\Carbon as Carbon;
use Illuminate\Support\Facades\Lang as Lang;
use Illuminate\Support\Facades\File as File;
use Illuminate\Support\Facades\DB as DB;
use Illuminate\Support\Facades\Schema as Schema;
use Illuminate\Support\Facades\Route;

class Zacl
{
    private $config = array();

    public function init($config = array())
    {
        $this->config = config('zacl.config');
        if ($config) {
            $this->config = array_merge($this->config, $config);
        }
    }

    public function set($uid, $role_id = 0)
    {
        $agent_key = $this->makeUagentKey($uid);
        Session::put($this->config['AUTH_SESSION_PREFIX'] . 'uid', $uid);
        Session::put($this->config['AUTH_SESSION_PREFIX'] . 'role_id', $role_id);
        Session::put($this->config['AUTH_SESSION_PREFIX'] . 'stime', Carbon::now()->getTimestamp());
        $cdata = $this->encode($agent_key . "\t". $uid . "\t". $role_id, config('app.key'));
        $this->dsetcookie('cdata', $cdata, 0, $this->config['AUTH_COOFIKE_PREFIX'], '/', '', true);

    }

    public function clear()
    {
        Session::forget($this->config['AUTH_SESSION_PREFIX'] . 'uid');
        Session::forget($this->config['AUTH_SESSION_PREFIX'] . 'role_id');
        if (Session::has($this->config['AUTH_SESSION_PREFIX'] . 'power')) {
            Session::forget($this->config['AUTH_SESSION_PREFIX'] . 'power');
        }
        $this->dsetcookie(
            'cdata',
            '',
            Carbon::now()->getTimestamp() - 3600,
            $this->config['AUTH_COOFIKE_PREFIX'],
            '/',
            '',
            true
        );
    }

    public function checkLogin()
    {
        if (Session::has($this->config['AUTH_SESSION_PREFIX'] . 'uid') &&
            Session::has($this->config['AUTH_SESSION_PREFIX'] . 'role_id')) {
            if (Session::get($this->config['AUTH_SESSION_PREFIX'] . 'uid') &&
                Session::get($this->config['AUTH_SESSION_PREFIX'] . 'role_id')) {
                $stime = Session::get($this->config['AUTH_SESSION_PREFIX'] . 'stime', 0);
                $now_time = Carbon::now()->getTimestamp();
                if ($now_time - $stime > 60) {
                    $this->set(
                        Session::get($this->config['AUTH_SESSION_PREFIX'] . 'uid'),
                        Session::get($this->config['AUTH_SESSION_PREFIX'] . 'role_id')
                    );
                }
                return true;
            }
        }
        return false;
    }

    public function check($controller_suffix = 'Controller')
    {
        $routeAction = Route::currentRouteAction();
        preg_match_all('/([a-z0-9A-Z]+\\\)?(\w+)@(\w+)/', $routeAction, $matchs);
        $controller_full = $matchs[2][0];  //类名
        $controller = str_replace($controller_suffix, '', $controller_full);
        $action = $matchs[3][0];    //方法名
        //不需要认证的模块，则放行
        if (isset($this->config['AUTH_LOGIN_NO'][$controller]) &&
            (($this->config['AUTH_LOGIN_NO'][$controller] == '*')
                || in_array($action, $this->config['AUTH_LOGIN_NO'][$controller])
            )
        ) {
            return true;
        }
        //没有登陆跳转到登陆页面
        if (!$this->checkLogin()) {
            //todo
            return $this->noLogin();
        }
        $power = $this->getRolePower(Session::get($this->config['AUTH_SESSION_PREFIX'] . 'role_id'));

        //临时的，记得删除-1 todo
        //$power = -1;

        if ($power == -1) {
            return true;
        } else {
            $privilege = Lang::has('privilege') ? Lang::get('privilege') : array();
            $controller = str_replace('Controller', '', $controller);
            if ($privilege) {
                if (isset($privilege[$controller]['power_rule']['module_hidden'])) {
                    if ($privilege[$controller]['power_rule']['module_hidden'] == 0) {
                        if (isset($privilege[$controller][$action])) {
                            if (isset($privilege[$controller]['power_rule'][$action]) &&
                                $privilege[$controller]['power_rule'][$action] == 1) {
                                return true;
                            } else {
                                if (isset($power[$controller][$action]) && $power[$controller][$action] == -1) {
                                    return true;
                                }
                            }
                        } else {    //没有设置$privilege[$controller][$action]一律通过
                            return true;
                        }
                    } elseif ($privilege[$controller]['power_rule']['module_hidden'] == 1) {
                        return true;
                    }
                }
            }
        }
        return $this->noPower();
    }

    /**
     * 检查模块和操作权限
     * @param string $controller   控制器
     * @param null   $action       动作
     * @return bool
     */
    public function checkPower($controller, $action = null)
    {
        if (empty($controller)) {
            return false;
        }

        $power = $this->getRolePower(Session::get($this->config['AUTH_SESSION_PREFIX'] . 'role_id'));
        if (empty($power)) {
            return false;
        }
        if ($power == -1) {
            return true;
        }

        if (empty($action) && isset($power[$controller]) && !empty($power[$controller])) {
            return true;
        } elseif (isset($power[$controller][$action])) {
            return true;
        } else {
            return false;
        }
    }

    public function getController(
        $config = array(),
        $controller_path = '',
        $controller_suffix = '',
        $str_namespace = ''
    ) {
        if (empty($config)) {
            $config = $this->config;
        }
        $this->createTableRole($config['AUTH_TABLE']);
        $this->createTableResource($config['AUTH_TABLE']);

        $controller_path = empty($controller_path) ? app_path() . '/Http/Controllers' : rtrim($controller_path, '/');
        $controller_suffix = empty($controller_suffix) ? 'Controller' : $controller_suffix;
        if ($str_namespace) {
            $str_namespace = "\\". trim($str_namespace, "\\") . "\\";
        }
        $return_data = array();

        if (File::isDirectory($controller_path)) {
            foreach (File::glob($controller_path . '/*'. $controller_suffix .'.php') as $filename) {
                $class_name = basename($filename, '.php');
                $controller = str_replace($controller_suffix, '', $class_name);
                $class_obj_name = $str_namespace ? $str_namespace . $class_name : $class_name;
                $class_methods = get_class_methods($class_obj_name);
                if (is_array($class_methods)) {
                    foreach ($class_methods as $action) {
                        //过滤魔术方法
                        if (substr($action, 0, 2) != '__' && !in_array($action, $config['AUTH_FILTER_METHOD'])) {
                            $return_data[$controller][$action] = -1;
                        }
                    }
                }
            }
        }
        if ($return_data) {
            foreach ($return_data as $key => $value) {
                $data = $condition = array();
                $data[$config['AUTH_TABLE']['resource']['field']['pid']] = 0;
                $condition[] = array(
                    $config['AUTH_TABLE']['resource']['field']['pid'] => 0
                );
                $data[$config['AUTH_TABLE']['resource']['field']['operate']] = $key;
                $condition[] = array(
                    $config['AUTH_TABLE']['resource']['field']['operate'] => $key
                );
                $db_res = DB::table($config['AUTH_TABLE']['resource']['name']);
                if ($condition) {
                    foreach ($condition as $k1 => $v1) {
                        foreach ($v1 as $k2 => $v2) {
                            $db_res->where($k2, '=', $v2);
                        }
                    }
                }
                $info = $db_res->first();
                if (empty($info)) {
                    $pid = DB::table($config['AUTH_TABLE']['resource']['name'])->insertGetId($data);
                } else {
                    $pid = $info[$config['AUTH_TABLE']['resource']['field']['id']];
                }

                if (is_array($value)) {
                    foreach ($value as $k2 => $v2) {
                        $data = $condition = array();
                        $data[$config['AUTH_TABLE']['resource']['field']['pid']] = $pid;
                        $condition[] = array(
                            $config['AUTH_TABLE']['resource']['field']['pid'] => $pid
                        );
                        $data[$config['AUTH_TABLE']['resource']['field']['operate']] = $k2;
                        $condition[] = array(
                            $config['AUTH_TABLE']['resource']['field']['operate'] => $k2
                        );
                        $db_res = DB::table($config['AUTH_TABLE']['resource']['name']);
                        if ($condition) {
                            foreach ($condition as $k1 => $v1) {
                                foreach ($v1 as $k2 => $v2) {
                                    $db_res->where($k2, '=', $v2);
                                }
                            }
                        }
                        $info = $db_res->first();
                        if (empty($info)) {
                            DB::table($config['AUTH_TABLE']['resource']['name'])->insertGetId($data);
                        }
                    }
                }
            }
        }
        return $return_data;
    }

    public function getRolePower($role_id = 0)
    {
        if ($this->config['AUTH_POWER_CACHE'] && Session::has($this->config['AUTH_SESSION_PREFIX'] . 'power')) {
            return Session::get($this->config['AUTH_SESSION_PREFIX'] . 'power');
        }

        if (empty($role_id) || empty($this->config['AUTH_TABLE']['role']['field']['power'])) {
            return false;
        }

        $role_info = DB::table($this->config['AUTH_TABLE']['role']['name'])
            ->where($this->config['AUTH_TABLE']['role']['field']['id'], '=', $role_id)->first();

        if ($role_info[$this->config['AUTH_TABLE']['role']['field']['power']] == -1) {
            $power = -1;
        } else {
            $resource = DB::table($this->config['AUTH_TABLE']['resource']['name'])->get();
            if (empty($resource)) {
                return false;
            }
            $power_value = explode(',', $role_info[$this->config['AUTH_TABLE']['role']['field']['power']]);
            $power = $resource2 = array();
            foreach ($resource as $k => $v) {
                $resource2[$v[$this->config['AUTH_TABLE']['resource']['field']['id']]] = $v;
            }
            foreach ($resource2 as $k => $v) {
                if ($v[$this->config['AUTH_TABLE']['resource']['field']['pid']] != 0
                    && in_array($v[$this->config['AUTH_TABLE']['resource']['field']['id']], $power_value)) {
                    $controller = $resource2[$v[$this->config['AUTH_TABLE']['resource']['field']['pid']]]
                    [$this->config['AUTH_TABLE']['resource']['field']['operate']];//模块
                    $action = $v[$this->config['AUTH_TABLE']['resource']['field']['operate']];//操作方法
                    $power[$controller][$action] = -1;
                }
            }
        }

        if ($this->config['AUTH_POWER_CACHE']) {
            Session::put($this->config['AUTH_SESSION_PREFIX'] . 'power', $power);
        }
        return $power;
    }

    private function noLogin()
    {
        return -2;
    }

    private function noPower()
    {
        return -1;
    }

    private function createTableRole($table_config)
    {
        if (!Schema::hasTable($table_config['role']['name'])) {
            Schema::create($table_config['role']['name'], function ($table) use ($table_config) {
                $table->engine = 'InnoDB';  //设置表的引擎
                $table->increments($table_config['role']['field']['id']);   //设置为自增键
                $table->integer($table_config['role']['field']['pid'])->unsigned()->default(0);
                $table->string($table_config['role']['field']['name'], 255)->default('');
                $table->text($table_config['role']['field']['power'])->nullable();
                $table->smallInteger($table_config['role']['field']['squad'])->default(100);

            });
            $setarr = array(
                $table_config['role']['field']['name'] => '超级管理员',
                $table_config['role']['field']['power'] => '-1',
            );
            DB::table($table_config['role']['name'])->insertGetId($setarr);
        }
    }
    private function createTableResource($table_config)
    {
        if (!Schema::hasTable($table_config['resource']['name'])) {
            Schema::create($table_config['resource']['name'], function ($table) use ($table_config) {
                $table->engine = 'InnoDB';  //设置表的引擎
                $table->increments($table_config['resource']['field']['id']);   //设置为自增键
                $table->integer($table_config['resource']['field']['pid'])->unsigned()->default(0);
                $table->string($table_config['resource']['field']['name'], 255)->default('');
                $table->string($table_config['resource']['field']['operate'], 255)->default('');
                $table->smallInteger($table_config['resource']['field']['squad'])->default(100);
                $table->index($table_config['resource']['field']['pid']);  //添加索引

            });
        }
    }


    //加密函数，可用decode()函数解密，$data：待加密的字符串或数组；$key：密钥；$expire 过期时间
    private function encode($data, $key = '', $expire = 0)
    {
        $string = serialize($data);
        $ckey_length = 4;
        $key = md5($key);
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = substr(md5(microtime()), -$ckey_length);

        $cryptkey = $keya.md5($keya.$keyc);
        $key_length = strlen($cryptkey);

        $string =  sprintf('%010d', $expire ? $expire + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);

        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }

        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }

        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        return $keyc.str_replace('=', '', base64_encode($result));
    }
    //encode之后的解密函数，$string待解密的字符串，$key，密钥
    private function decode($string, $key = '')
    {
        $ckey_length = 4;
        $key = md5($key);
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = substr($string, 0, $ckey_length);

        $cryptkey = $keya.md5($keya.$keyc);
        $key_length = strlen($cryptkey);

        $string =  base64_decode(substr($string, $ckey_length));
        $string_length = strlen($string);

        $result = '';
        $box = range(0, 255);

        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }

        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }

        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0)
            && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return unserialize(substr($result, 26));
        } else {
            return '';
        }
    }

    /**
     * 产生一个用户头信息密钥
     * @param string $str   字符串源
     * @return string
     */
    private function makeUagentKey($str)
    {
        return md5(md5($str).$_SERVER['HTTP_USER_AGENT']);
    }
    /**
     * 封装setcookie函数
     * @param string   $var           cookie名
     * @param string   $value         cookie值
     * @param int      $life          生命周期
     * @param string   $prefix        前缀
     * @param string   $path          路径
     * @param string   $domain        有效域
     * @param bool     $httponly      防止xss设置
     */
    private function dsetcookie($var, $value = '', $life = 0, $prefix = '', $path = '', $domain = '', $httponly = false)
    {
        $now_time = Carbon::now()->getTimestamp();

        $var = $prefix.$var;

        if ($value == '' || $life < 0) {
            $value = '';
            $life = -1;
        }
        if (defined('IN_MOBILE')) {
            $httponly = false;
        }
        $life = $life > 0 ? $now_time + $life : ($life < 0 ? $now_time - 31536000 : 0);
        $path = $httponly && PHP_VERSION < '5.2.0' ? $path.'; HttpOnly' : $path;

        $secure = $_SERVER['SERVER_PORT'] == 443 ? 1 : 0;
        $domain = $domain ? $domain : '/';
        if (PHP_VERSION < '5.2.0') {
            setcookie($var, $value, $life, $path, $domain, $secure);
        } else {
            setcookie($var, $value, $life, $path, $domain, $secure, $httponly);
        }
    }
}
