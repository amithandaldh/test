<?php

use common\models\base\Fruit;
use yii\helpers\Html;
use yii\helpers\Url;
use yii\grid\ActionColumn;
use yii\grid\GridView;
use yii\widgets\Pjax;
/** @var yii\web\View $this */
/** @var yii\data\ActiveDataProvider $dataProvider */

$this->title = Yii::t('app', 'Fruits');
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="fruit-index">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a(Yii::t('app', 'Fruit Summary'), ['index'], ['class' => 'btn btn-success']) ?>
    </p>

    <?php Pjax::begin(); ?>

    <?= GridView::widget([
        'dataProvider' => $dataProvider,
        'filterModel' => $searchModel,
        'columns' => [
            //['class' => 'yii\grid\SerialColumn'],

            'id',
            //'guid',
            'name',
            'genus',
            'family',
            'order',
            'carbohydrates',
            'protein',
            'fat',
            'calories',
            'sugar',
            //'created_on',
            [
                'attribute' => 'is_favorite',
                'label' => 'Favorite',
                'format' => 'raw',
                'filter' => false,
                'value' => function ($data) {
                    return (($data->is_favorite) == 1) ? \Yii::t('yii', 'Yes') : \Yii::t('yii', 'No');
                },
            ]
        ],
    ]); ?>

    <?php Pjax::end(); ?>

</div>
