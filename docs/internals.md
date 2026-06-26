# Internals

## Unit testing

The package is tested with [PHPUnit](https://phpunit.de/). To run tests:

```shell
composer run test
```

## Mutation testing

The package tests are checked with [Infection](https://infection.github.io/) mutation framework. To run it:

```shell
composer run infection
```

## Static analysis

The code is statically analyzed with [Psalm](https://psalm.dev/). To run static analysis:

```shell
composer run psalm
```

## Code quality and style

Use [Rector](https://github.com/rectorphp/rector) to automate code refactoring and keep the codebase up to date with modern PHP features:

```shell
composer run rector
```

Use [PHP-CS-Fixer](https://github.com/PHP-CS-Fixer/PHP-CS-Fixer) to format your code according to the `PER-CS3.0` coding standard:

```shell
composer run cs-fix
```

## Dependencies

This package uses [composer-require-checker](https://github.com/maglnet/ComposerRequireChecker) to check if all dependencies are correctly defined in `composer.json`. To run the checker:

```shell
composer dependency-analyser
```
