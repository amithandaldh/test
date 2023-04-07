<?php

namespace common\models\caching;
use common\models\caching\base\Cache as BaseCache;
use Yii;

/**
 * Description of ModelCache
 *
 * @author Amit Handa
 */
class ModelCache extends BaseCache
{
    const RETURN_TYPE_OBJECT = 'object';
    const RETURN_ALL = 'all';
    const RETURN_ONE = 'one';
    
    const IS_ACTIVE_YES = 1;
    const IS_ACTIVE_NO = 0;
    const IS_DELETED_YES = 1;
    const IS_DELETED_NO = 0;

    public function __construct($className, $params, $enableCaching = false)
    {
        //generating a new key for the cache
        $this->key = $className . '-' . md5(base64_encode(serialize($params)));

        if (isset($params['forceCache']) && $params['forceCache']) {
            //$this->enableCaching = true;
        }

        if ($this->enableCaching && !empty($params['cacheTime']) && $params['cacheTime'] > 0) {
            $this->cachePeriod = (int) $params['cacheTime'];
        }

        parent::__construct();
    }

    public function getOrSet($modelAQ, $returnAllOrOne = 'all')
    {
        if ($this->enableCaching) {
            if (!$this->exists()) {
                $data = $modelAQ->{$returnAllOrOne}();
                $this->set(base64_encode(serialize($data)));
            }
            else {
                $data = unserialize(base64_decode($this->get()));
            }
        }
        else {
            $data = $modelAQ->{$returnAllOrOne}();
        }

        return $data;
    }

    public function getOrSetByParams($modelAQ, $params = [])
    {
        $class = $modelAQ->modelClass;
        $tableName = $class::tableName();
        
        if (isset($params['isActive'])) {
            $modelAQ->andWhere($tableName . '.is_active = :isActive', [':isActive' => $params['isActive']]);
        }

        if (isset($params['isDeleted'])) {
            $modelAQ->andWhere($tableName . '.is_deleted = :isDeleted OR '.$tableName.'.is_deleted IS NULL', [':isDeleted' => $params['isDeleted']]);
        }
        
        if (isset($params['offset']) && $params['offset'] >= 0) {
            $modelAQ->offset($params['offset']);
        }

        if (isset($params['limit']) && $params['limit'] > 0) {
            $modelAQ->limit($params['limit']);
        }

        // sort order
        if (!empty($params['orderBy'])) {
            if (is_array($params['orderBy'])) {

                $modelAQ->orderBy($params['orderBy']);
            }
            else {
                if (isset($params['orderDirection'])) {
                    $modelAQ->orderBy([$params['orderBy'] => $params['orderDirection']]);
                }
                else {
                    $modelAQ->orderBy([$params['orderBy'] => SORT_ASC]);
                }
            }
        }

        // having clause
        if (isset($params['having'])) {
            $modelAQ->having($params['having']);
        }

        if (isset($params['groupBy'])) {
            $modelAQ->groupBy($params['groupBy']);
        }

        if (isset($params['returnModel']) && $params['returnModel']) {
            return $modelAQ;
        }

        // result format : array or object
        if (!isset($params['resultFormat']) || $params['resultFormat'] != self::RETURN_TYPE_OBJECT) {
            $modelAQ->asArray();
        }

        if (isset($params['returnAll']) && $params['returnAll']) {
            $returnAllOrOne = self::RETURN_ALL;
        }
        else {
            $returnAllOrOne = (isset($params['resultCount']) && $params['resultCount'] == self::RETURN_ALL) ? self::RETURN_ALL : self::RETURN_ONE;
        }

        if ((isset($params['checkExists']) && $params['checkExists']) || (isset($params['existOnly']) && $params['existOnly']) || (isset($params['exists']) && $params['exists'])
        ) {
            $returnAllOrOne = 'exists';
        }

        if ((isset($params['countOnly']) && $params['countOnly']) || (isset($params['count']) && $params['count'])
        ) {
            $returnAllOrOne = 'count';
        }

        if (isset($params['forceCache']) && $params['forceCache'] === FALSE) {
            $this->enableCaching = false;
        }

        if (isset($params['print']) && $params['print'] === TRUE) {
            echo $modelAQ->createCommand()->rawSql;die;
        }

        //echo $modelAQ->createCommand()->rawSql;die;

        return $this->getOrSet($modelAQ, $returnAllOrOne);
    }

    public static function setFlag($key = null)
    {
        $list = [self::IS_ACTIVE_YES => 'Yes', self::IS_ACTIVE_NO => 'No'];
        return isset($list[$key]) ? $list[$key] : $list;
    }

    public static function testEmail()
    {
        return [];
    }
}