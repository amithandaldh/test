<?php

namespace console\controllers;

use common\models\caching\ModelCache;
use common\models\Fruit;
use Yii;

/**
 * Description of TestController
 *
 * @author Amit Handa
 */
class FruitsController extends \yii\console\Controller
{
    public function actionFetch()
    {
        $json = file_get_contents('https://fruityvice.com/api/fruit/all');
        $obj = json_decode($json);
        if(!empty($obj)) {
            foreach ($obj as $key => $value) {
                $model = Fruit::findById($value->id, ['resultFormat' => ModelCache::RETURN_TYPE_OBJECT]);
                if($model === null) {
                    $model = new Fruit();
                }
                $model->id = $value->id;
                $model->name = $value->name;
                $model->genus = $value->genus;
                $model->family = $value->family;
                $model->order = $value->order;
                if(isset($value->nutritions) && !empty($value->nutritions)) {
                    $model->carbohydrates = $value->nutritions->carbohydrates;
                    $model->protein = $value->nutritions->protein;
                    $model->fat = $value->nutritions->fat;
                    $model->calories = $value->nutritions->calories;
                    $model->sugar = $value->nutritions->sugar;
                }
                if(!$model->validate() || !$model->save()) {
                    throw new \components\exceptions\AppException("Sorry, You trying to access type doesn't exist or deleted.");
                }
            }
        }

        Yii::$app->mailer->compose()
        ->setTo('amithanda.ldh@gmail.com')
        ->setFrom(['noreply@gmail.com' => 'Amit Handa'])
        ->setSubject('Fruits saved successfully!')
        ->setTextBody('All fruits are saved successfully.')
        ->send();
        echo 'Done';
    }
}