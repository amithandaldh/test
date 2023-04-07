<?php

namespace components\exceptions;

/**
 * Description of AppException
 *
 * @author Amit Handa<insphere.amit@gmail.com>
 */
class AppException extends \yii\base\UserException
{
    public function __construct($message = "", $httpCode = 0, $code = 0, \Exception $previous = null)
    {
        if ($httpCode > 0) {
            throw new \yii\web\HttpException($httpCode, $message, $code, $previous);
        }
        else {
            parent::__construct($message, $code, $previous);
        }
    }
}
