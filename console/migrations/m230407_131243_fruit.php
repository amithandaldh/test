<?php

use yii\db\Migration;

/**
 * Class m230407_131243_fruit
 */
class m230407_131243_fruit extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->db->createCommand("CREATE TABLE `fruit` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `guid` varchar(36) NOT NULL,
            `name` varchar(64) NOT NULL,
            `genus` varchar(64) NOT NULL,
            `family` varchar(64) NOT NULL,
            `order` varchar(64) NOT NULL,
            `carbohydrates` decimal(5,2) NOT NULL DEFAULT 0.00,
            `protein` decimal(5,2) NOT NULL DEFAULT 0.00,
            `fat` decimal(5,2) NOT NULL DEFAULT 0.00,
            `calories` decimal(5,2) NOT NULL DEFAULT 0.00,
            `sugar` decimal(5,2) NOT NULL DEFAULT 0.00,
            `is_favorite` tinyint(1) NOT NULL DEFAULT 0,
            `created_on` int(11) DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `guid` (`guid`)
          ) ENGINE=InnoDB DEFAULT CHARSET=latin1")->execute();
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        echo "m230407_131243_fruit cannot be reverted.\n";

        return false;
    }

    /*
    // Use up()/down() to run migration code without a transaction.
    public function up()
    {

    }

    public function down()
    {
        echo "m230407_131243_fruit cannot be reverted.\n";

        return false;
    }
    */
}
