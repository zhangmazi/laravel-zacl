<?php
namespace Zhangmazi\Zacl\Facades;

use Illuminate\Support\Facades\Facade;

class Zacl extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'zacl';
    }
}
