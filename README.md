```php
<?php

$comment = new Comment(); // create some entity
// ... do work on entity

$em->persist($comment);
$em->flush(); // entity must be persisted and flushed before AclManager can act on it (needs identifier)
$aclManager = $this->get('problematic.acl_manager');
$aclManager->addPermission($comment, $userEntity, MaskBuilder::MASK_OWNER);

$aclManager->revokePermission($comment, $userEntity, MaskBUILDER::MASK_DELETE);

$aclManager->deleteAcl($comment);
$em->remove($comment);
$em->flush();

```
