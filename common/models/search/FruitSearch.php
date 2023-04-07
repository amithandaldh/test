<?php

namespace common\models\search;

use Yii;
use yii\base\Model;
use yii\data\ActiveDataProvider;
use common\models\Fruit;

/**
 * Description of FruitSearch
 *
 * @author Amit Handa
 */
class FruitSearch extends Fruit
{
    public $name;
    public $family;
    public $is_favorite;

    public function rules()
    {
        return [
            [['name', 'family'], 'string'],
            ['is_favorite', 'integer']
        ];
    }

    /**
     * @inheritdoc
     */
    public function scenarios()
    {
        return Model::scenarios();
    }

    /**
     * Creates data provider instance with search query applied
     *
     * @param array $params
     *
     * @return ActiveDataProvider
     */
    public function search($params)
    {
        $query = Fruit::find();

        $dataProvider = new ActiveDataProvider([
            'query' => $query,
            'pagination' => [
                'pageSize' => 20
            ],
             'sort' => [
                'attributes' => [
                    'name','created_on'
                ],
                'defaultOrder' => ['name' => SORT_ASC]]
        ]);

        $this->load($params);
        if (!$this->validate()) {
            return $dataProvider;
        }
        $query->andFilterWhere(['like', 'name', $this->name]);
        $query->andFilterWhere(['like', 'family', $this->family]);
        $query->andFilterWhere(['is_favorite' => $this->is_favorite]);
        
        //echo $query->createCommand()->rawSql;
        return $dataProvider;
    }

}
