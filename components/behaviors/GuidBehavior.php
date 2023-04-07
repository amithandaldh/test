<?php
namespace components\behaviors;

use yii\db\ActiveRecord;

/**
 * Description of GuidBehavior
 *
 * @author Amit Handa<amithanda.ldh@gmail.com>
 */
class GuidBehavior extends \yii\base\Behavior
{
    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
    }
    
    public function events()
    {
        return [
            ActiveRecord::EVENT_BEFORE_INSERT => 'beforeSave',
            ActiveRecord::EVENT_BEFORE_UPDATE => 'beforeUpdate',
            ActiveRecord::EVENT_BEFORE_VALIDATE => 'beforeValidate',
                
        ];
    }
    
    //Check guid is matching or not before updating
    public function beforeUpdate($event)
    {
        $oldValues = $this->owner->oldPrimaryKey;
        if(is_array($oldValues) && isset($oldValues['guid']) 
                && !empty($oldValues['guid']) && $this->owner->guid !== $oldValues['guid']) {
            $this->owner->addError('guid', 'GUID is not matching');
            $event->isValid = false;//stops updating of record
            return false;
        }
    }
    
    //Generate a unique guid before saving
    public function beforeSave($event)
    {
        if (empty($this->owner->guid)) {
            $this->_GenerateGuid();
        }
        
        return true;
    }
    
    //Generate a unique guid before saving
    public function beforeValidate($event)
    {
        if ( $this->owner->isNewRecord && empty($this->owner->guid)) {
            $this->_GenerateGuid();
        }
        
        return true;
    }
    
    private function _GenerateGuid()
    {
        //making sure that the GUID is unique
        while(true) {
            $guid = \components\Helper::GUIDv4();
            $exists = $this->owner->find()->where('guid = :guid', [':guid' => $guid])->exists();
            if (!$exists) {
                $this->owner->guid = $guid;
                break;
            }
        }
    }
}
