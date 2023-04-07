# test

# Download or clone the code from given link: https://github.com/amithandaldh/test.git

# After download and extract or clone the code you need to follow below steps

# go to root directory from terminal and run below command for create hidden files
php init

# Create a DB in mysql
# Do DB Settings in given file path common/config/main-local.php

# Run Migration to import DB
php yii migrate

# Run composer install or update
composer update

# Create VirtualHost for frontend/web/ directory apache\conf\extra\httpd-vhosts.conf

# Restart your apache server and run the project

Write a console script for getting all fruits from https://fruityvice.com/ and saving them into local DB (MySQL or PostgreSQL).
# run this command from terminal to fetch all fruits, for example:
php yii fruits/fetch