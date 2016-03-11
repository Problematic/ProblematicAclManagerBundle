## Installation ##

Add this bundle to your `composer.json` file:

```json
{
    "require": {
        "problematic/acl-manager-bundle": "dev-master"
    }
}
```

Register the bundle in `app/AppKernel.php`:

```php
<?php

// app/AppKernel.php
public function registerBundles()
{
    return array(
        // ...
        new Problematic\AclManagerBundle\ProblematicAclManagerBundle(),
    );
}
```

If you haven't configured the ACL enable it in `app/config/security.yml`:

```yaml
# app/config/security.yml
security:
    acl:
        connection: default
```

Finally run the ACL init command

    php app/console init:acl

## Usage ##

```php
<?php

$comment = new Comment(); // create some entity
// ... do work on entity

$em->persist($comment);
$em->flush(); // entity must be persisted and flushed before AclManager can act on it (needs identifier)
$aclManager = $this->get('problematic.acl_manager');

// Adds a permission no matter what other permissions existed before
$aclManager->addObjectPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
// Or:
$aclManager->addObjectPermission($comment, MaskBuilder::MASK_OWNER);
// Replaces all current permissions with this new one
$aclManager->setObjectPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
$aclManager->revokePermission($comment, MaskBuilder::MASK_DELETE, $userEntity);
$aclManager->revokeAllObjectPermissions($comment, $userEntity);

// Same with class permissions:
$aclManager->addClassPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
$aclManager->setClassPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
$aclManager->revokePermission($comment, MaskBuilder::MASK_DELETE, $userEntity, 'class');
$aclManager->revokeAllClassPermissions($comment, $userEntity);

// You can alse use object-field...
$aclManager->addObjectFieldPermission($comment, 'title', MaskBuilder:MASK_EDIT, $userEntity);
$aclManager->setObjectFieldPermission($comment, 'title', MaskBuilder:MASK_EDIT, $userEntity);
$aclManager->revokeFieldPermission($comment,, 'title' MaskBuilder::MASK_DELETE, $userEntity);
$aclManager->revokeAllObjectFieldPermissions($comment, 'title', $userEntity);
// ...and class-field scope permissions :
$aclManager->addClassFieldPermission($comment, 'title', MaskBuilder:MASK_EDIT, $userEntity);
$aclManager->setClassFieldPermission($comment, 'title', MaskBuilder:MASK_EDIT, $userEntity);
$aclManager->revokeFieldPermission($comment,, 'title' MaskBuilder::MASK_DELETE, $userEntity, 'class');
$aclManager->revokeAllClassFieldPermissions($comment, 'title', $userEntity);

$aclManager->deleteAclFor($comment);
$em->remove($comment);
$em->flush();

```

If no `$userEntity` is provided, the current session user will be used instead.

If you'll be doing work on a lot of entities, use AclManager#preloadAcls():

```php
<?php

$products = $repo->findAll();

$aclManager = $this->get('problematic.acl_manager');
$aclManager->preloadAcls($products);

// ... carry on
```
