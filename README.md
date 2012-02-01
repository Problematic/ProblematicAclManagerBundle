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
$aclManager->revokeObjectPermission($comment, MaskBUILDER::MASK_DELETE, $userEntity);
$aclManager->revokeObjectAllPermissions($comment, $userEntity);

// Same with class permissions:
$aclManager->addClassPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
$aclManager->setClassPermission($comment, MaskBuilder::MASK_OWNER, $userEntity);
$aclManager->revokeClassPermission($comment, MaskBUILDER::MASK_DELETE, $userEntity);
$aclManager->revokeClassAllPermissions($comment, $userEntity);

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
