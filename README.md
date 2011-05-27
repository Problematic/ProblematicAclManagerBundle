```php
<?php

$comment = new Comment(); // create some entity
// ... do work on entity

$em->persist($comment);
$em->flush(); // entity must be persisted and flushed before AclManager can act on it (needs identifier)

$aclManager = $this->get('acl.manager');
$permissions = $aclManager->createPermissionContext('object', $userEntity, MaskBuilder::MASK_OWNER);
$aclManager->addPermissionContext($permissions);

$aclManager->loadAcl($comment)->processPermissions()->installDefaults();

?>
```