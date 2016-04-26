<?php
/**
 * 验证权限控制
 * author:ninja911
 * email:ninja911#qq.com
 * date:2015-05-06 15:58
 */
namespace Zhangmazi\Zacl;

use Illuminate\Support\ServiceProvider;

class ZaclServiceProvider extends ServiceProvider
{
    /**
     * 指定是否延缓提供者加载
     *
     * @var bool
     */
    //protected $defer = true;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config/config.php' => config_path('zacl/config.php'),
        ], 'config');
    }

    /**
     * 注册服务提供者
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('zacl', function ($app) {
            return new Zacl();
        });
    }
}
