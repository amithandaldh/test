<?php

namespace common\models\base;

use Yii;

/**
 * This is the model class for table "fruit".
 *
 * @property int $id
 * @property string $guid
 * @property string $name
 * @property string $genus
 * @property string $family
 * @property string $order
 * @property float $carbohydrates
 * @property float $protein
 * @property float $fat
 * @property float $calories
 * @property float $sugar
 * @property int|null $created_on
 */
class Fruit extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'fruit';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['guid', 'name', 'genus', 'family', 'order'], 'required'],
            [['carbohydrates', 'protein', 'fat', 'calories', 'sugar'], 'number'],
            [['created_on'], 'integer'],
            [['guid'], 'string', 'max' => 36],
            [['name', 'genus', 'family', 'order'], 'string', 'max' => 64],
            [['guid'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => Yii::t('app', 'ID'),
            'guid' => Yii::t('app', 'Guid'),
            'name' => Yii::t('app', 'Name'),
            'genus' => Yii::t('app', 'Genus'),
            'family' => Yii::t('app', 'Family'),
            'order' => Yii::t('app', 'Order'),
            'carbohydrates' => Yii::t('app', 'Carbohydrates'),
            'protein' => Yii::t('app', 'Protein'),
            'fat' => Yii::t('app', 'Fat'),
            'calories' => Yii::t('app', 'Calories'),
            'sugar' => Yii::t('app', 'Sugar'),
            'created_on' => Yii::t('app', 'Created On'),
        ];
    }
}
