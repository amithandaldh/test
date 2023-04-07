<?php

namespace common\models\base;

use Yii;

/**
 * This is the model class for table "fruit_nutrition".
 *
 * @property int $id
 * @property int $fruit_id
 * @property float $carbohydrates
 * @property float $protein
 * @property float $fat
 * @property float $calories
 * @property float $sugar
 *
 * @property Fruit $fruit
 */
class FruitNutrition extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'fruit_nutrition';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['fruit_id'], 'required'],
            [['fruit_id'], 'integer'],
            [['carbohydrates', 'protein', 'fat', 'calories', 'sugar'], 'number'],
            [['fruit_id'], 'exist', 'skipOnError' => true, 'targetClass' => Fruit::class, 'targetAttribute' => ['fruit_id' => 'id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => Yii::t('app', 'ID'),
            'fruit_id' => Yii::t('app', 'Fruit ID'),
            'carbohydrates' => Yii::t('app', 'Carbohydrates'),
            'protein' => Yii::t('app', 'Protein'),
            'fat' => Yii::t('app', 'Fat'),
            'calories' => Yii::t('app', 'Calories'),
            'sugar' => Yii::t('app', 'Sugar'),
        ];
    }

    /**
     * Gets query for [[Fruit]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getFruit()
    {
        return $this->hasOne(Fruit::class, ['id' => 'fruit_id']);
    }
}
