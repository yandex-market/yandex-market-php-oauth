# PHP-библиотека OAuth-авторизации API Яндекса

Протокол OAuth 2.0 позволяет приложениям работать с сервисами Яндекса от имени пользователя. Доступ каждого приложения явно ограничивается правами, заданными при его регистрации. О базовых принципах OAuth, а также об особенностях протокола в Яндексе читайте раздел [Реализация OAuth в Яндексе](https://tech.yandex.ru/oauth/doc/dg/concepts/ya-oauth-intro-docpage/) документации. Библиотека написана на языке PHP и содержит методы для OAuth-авторизации в Яндексе.  

* [Требования](#Требования)
* [Лицензия](#Лицензия)
* [Установка](#Установка)
* [Использование](#Использование)

## Требования

* PHP 5.6 или выше.
* Зарегистрированное приложение.

Подробнее см. раздел [С чего начать](https://github.com/yandex-market/yandex-market-php-oauth/wiki/С-чего-начать) в Wiki.

## Лицензия

Библиотека распространяется по [лицензии MIT](LICENSE.txt).

## Установка

Библиотека устанавливается с помощью пакетного менеджера [Composer](https://getcomposer.org).

1. Добавьте библиотеку в файл `composer.json` вашего проекта:

   ```json
   {
       "require": {
           "yandex-market/yandex-market-php-oauth": "*"
       }
   }
   ```

2. Включите автозагрузчик Composer в код проекта:

   ```php
   require __DIR__ . '/vendor/autoload.php';
   ```   


## Использование

См. [Wiki](https://github.com/yandex-market/yandex-market-php-oauth/wiki) и [документацию OAuth в Яндексе](https://tech.yandex.ru/oauth/doc/dg/concepts/about-docpage/).
