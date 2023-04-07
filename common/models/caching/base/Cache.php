<?php

namespace common\models\caching\base;

use Yii;

/**
 * Description of Cache
 *
 * @author Amit Handa
 */
class Cache extends \yii\base\Component
{
    const CACHE_30_SECS = 30;
    const CACHE_60_SECS = 60;
    const CACHE_120_SECS = 120;
    const CACHE_300_SECS = 300;
    const CACHE_1000_SECS = 1000;

    private $cache;
    protected $cachePeriod = self::CACHE_300_SECS; // 5 min
    protected $key;
    protected $enableCaching = false;
    
    public function init()
    {
        $this->cache = Yii::$app->cache;
        
        parent::init();
    }
    
    public function setCachePeriod($cachePeriod = self::CACHE_120_SECS)
    {
        $this->cachePeriod = $cachePeriod;
        
        return $this;
    }
    
    private function setCache($key, $data, $cachePeriodInSecs = 0)
    {
        $cachePeriod = ($cachePeriodInSecs == 0) ? $this->cachePeriod : $cachePeriodInSecs;
        
        return $this->cache->set($key, $data, $cachePeriod);
    }
    
    private function getCache($key)
    {
        return $this->cache->get($key);
    }
    
    private function checkKeyExists($key)
    {
        return $this->cache->exists($key);
    }
    
    private function deleteCache($key)
    {
        return $this->cache->delete($key);
    }
    
    public function exists()
    {
        return $this->checkKeyExists($this->key);
    }
    
    public function get()
    {
        return $this->getCache($this->key);
    }

    public function set($data)
    {
        return $this->setCache($this->key, $data);
    }

    public function delete()
    {
        return $this->deleteCache($this->key);
    }
}
