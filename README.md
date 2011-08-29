```php
<?php

$comment = new Comment(); // create some entity
// ... do work on entity

$em->persist($comment);
$em->flush(); // entity must be persisted and flushed before AclManager can act on it (needs identifier)
$aclManager = $this->get('security.acl.manager');
$aclManager->add($comment, $userEntity, MaskBuilder::MASK_OWNER);

$aclManager->delete($comment);
$em->remove($comment);
$em->flush();

```
