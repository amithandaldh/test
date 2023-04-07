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
$this->registerJs('StatusController.update();');
?>
<div class="fruit-index">

    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <?= Html::a(Yii::t('app', 'Favorite Fruit Summary'), ['favorite-fruit'], ['class' => 'btn btn-success']) ?>
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
            //'carbohydrates',
            //'protein',
            //'fat',
            //'calories',
            //'sugar',
            //'created_on',
            [
                'attribute' => 'is_favorite',
                'label' => 'Favorite',
                'format' => 'raw',
                'filter' => false,
                'contentOptions' => function ($model) {
                    return [
                        'class' => 'updateStatusGrid',
                        'data-url' => Url::toRoute(['fruit/status', 'guid' => $model->guid])
                    ];
                },
                'value' => function ($data) {
                    return (($data->is_favorite) == 1) ? "<a href='javascript:void(0)' title='Yes'>" . \Yii::t('yii', 'Yes') . "</a>" : "<a href='javascript:void(0)' title='No'>" . \Yii::t('yii', 'No') . "</a>";
                },
            ],
            [
                'class' => ActionColumn::className(),
                'urlCreator' => function ($action, Fruit $model, $key, $index, $column) {
                    return Url::toRoute([$action, 'id' => $model->id]);
                 }
            ],
        ],
    ]); ?>

    <?php Pjax::end(); ?>

</div>