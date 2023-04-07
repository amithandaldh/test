<?php

namespace frontend\controllers;

use Yii;
use common\models\Fruit;
use common\models\caching\ModelCache;
use common\models\search\FruitSearch;
use yii\data\ActiveDataProvider;
use yii\web\Controller;
use yii\web\NotFoundHttpException;
use yii\filters\VerbFilter;

/**
 * FruitController implements the CRUD actions for Fruit model.
 */
class FruitController extends Controller
{
    /**
     * @inheritDoc
     */
    public function behaviors()
    {
        return array_merge(
            parent::behaviors(),
            [
                'verbs' => [
                    'class' => VerbFilter::className(),
                    'actions' => [
                        'delete' => ['POST'],
                    ],
                ],
            ]
        );
    }

    /**
     * Lists all Fruit models.
     *
     * @return string
     */
    public function actionIndex()
    {
        $searchModel = new FruitSearch();
        $dataProvider = $searchModel->search(\Yii::$app->request->queryParams);

        return $this->render('index', [
            'searchModel' => $searchModel,
            'dataProvider' => $dataProvider
        ]);
    }

    /**
     * Displays a single Fruit model.
     * @param int $id ID
     * @return string
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionView($id)
    {
        return $this->render('view', [
            'model' => $this->findModel($id),
        ]);
    }

    /**
     * Creates a new Fruit model.
     * If creation is successful, the browser will be redirected to the 'view' page.
     * @return string|\yii\web\Response
     */
    public function actionCreate()
    {
        $model = new Fruit();

        if ($this->request->isPost) {
            if ($model->load($this->request->post()) && $model->save()) {
                return $this->redirect(['view', 'id' => $model->id]);
            }
        } else {
            $model->loadDefaultValues();
        }

        return $this->render('create', [
            'model' => $model,
        ]);
    }

    /**
     * Updates an existing Fruit model.
     * If update is successful, the browser will be redirected to the 'view' page.
     * @param int $id ID
     * @return string|\yii\web\Response
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionUpdate($id)
    {
        $model = $this->findModel($id);

        if ($this->request->isPost && $model->load($this->request->post()) && $model->save()) {
            return $this->redirect(['view', 'id' => $model->id]);
        }

        return $this->render('update', [
            'model' => $model,
        ]);
    }

    /**
     * Deletes an existing Fruit model.
     * If deletion is successful, the browser will be redirected to the 'index' page.
     * @param int $id ID
     * @return \yii\web\Response
     * @throws NotFoundHttpException if the model cannot be found
     */
    public function actionDelete($id)
    {
        $this->findModel($id)->delete();

        return $this->redirect(['index']);
    }

    /**
     * Finds the Fruit model based on its primary key value.
     * If the model is not found, a 404 HTTP exception will be thrown.
     * @param int $id ID
     * @return Fruit the loaded model
     * @throws NotFoundHttpException if the model cannot be found
     */
    protected function findModel($id)
    {
        if (($model = Fruit::findOne(['id' => $id])) !== null) {
            return $model;
        }

        throw new NotFoundHttpException(Yii::t('app', 'The requested page does not exist.'));
    }

    /**
     * Lists all Fruit models.
     *
     * @return string
     */
    public function actionFavoriteFruit()
    {
        $searchModel = new FruitSearch();
        $searchModel->is_favorite = ModelCache::IS_ACTIVE_YES;
        $dataProvider = $searchModel->search(\Yii::$app->request->queryParams);

        return $this->render('favorite-fruit', [
            'searchModel' => $searchModel,
            'dataProvider' => $dataProvider
        ]);
    }

    public function actionStatus($guid)
    {
        if (!Yii::$app->request->isAjax) {
            throw new \components\exceptions\AppException("Oops! Your request is not valid.");
        }

        try {
            $count = Fruit::findByKeys(['isFavorite' => ModelCache::IS_ACTIVE_YES, 'selectCols' => ['id'], 'countOnly' => true]);
            if($count >= 10) {
                throw new \components\exceptions\AppException("Oops! Limit exceeded, You can choose 10 fruits.");
            }
            $model = Fruit::findByGuid($guid, ['resultFormat' => ModelCache::RETURN_TYPE_OBJECT]);
            $status = ($model->is_favorite == ModelCache::IS_ACTIVE_YES) ? ModelCache::IS_ACTIVE_NO : ModelCache::IS_ACTIVE_YES;
            $model->is_favorite = $status;
            $model->save(TRUE, ['is_favorite']);

            return \components\Helper::outputJsonResponse(['success' => 1, 'status' => $status]);
        }
        catch (\Exception $ex) {
            throw new \components\exceptions\AppException($ex->getMessage());
        }
    }
}
