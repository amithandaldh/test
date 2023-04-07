<?php

use yii\helpers\Html;

/** @var yii\web\View $this */
/** @var common\models\base\Fruit $model */

$this->title = Yii::t('app', 'Create Fruit');
$this->params['breadcrumbs'][] = ['label' => Yii::t('app', 'Fruits'), 'url' => ['index']];
$this->params['breadcrumbs'][] = $this->title;
?>
<div class="fruit-create">

    <h1><?= Html::encode($this->title) ?></h1>

    <?= $this->render('_form', [
        'model' => $model,
    ]) ?>

</div>
