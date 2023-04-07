<?php

namespace common\models;

use Yii;
use common\models\base\FruitNutrition as BaseFruitNutrition;

class FruitNutrition extends BaseFruitNutrition
{    
    public function behaviors()
    {
        return [
            [
                'class' => \yii\behaviors\TimestampBehavior::className(),
                'attributes' => [
                    \yii\db\ActiveRecord::EVENT_BEFORE_INSERT => ['created_on'],
                ],
            ]
        ];
    }

    private static function findByParams($params = [])
    {
        $modelAQ = self::find();
        $tableName = self::tableName();

        if (isset($params['selectCols']) && !empty($params['selectCols'])) {
            $modelAQ->select($params['selectCols']);
        } else {
            $modelAQ->select($tableName . '.*');
        }

        if (isset($params['id'])) {
            $modelAQ->andWhere($tableName . '.id =:id', [':id' => $params['id']]);
        }

        if (isset($params['fruitId'])) {
            $modelAQ->andWhere($tableName . '.fruit_id =:fruitId', [':fruitId' => $params['fruitId']]);
        }

        return (new caching\ModelCache(self::className(), $params))->getOrSetByParams($modelAQ, $params);
    }
}