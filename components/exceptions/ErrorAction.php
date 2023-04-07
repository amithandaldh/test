<?php
namespace components\exceptions;

/**
 * Description of ErrorAction
 *
 * @author Amit Handa<insphere.amit@gmail.com>
 */
class ErrorAction extends \yii\web\ErrorAction
{

    protected function renderAjaxResponse()
    {
        return $this->getExceptionMessage();
    }

    protected function getViewRenderParams()
    {
        $baseViewRenderParams = parent::getViewRenderParams();
        
        return \yii\helpers\ArrayHelper::merge(['statusCode' => $this->getExceptionCode()], $baseViewRenderParams);
    }

}
