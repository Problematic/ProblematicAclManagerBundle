<?php

namespace Problematic\AclManagerBundle\Acl;

use Problematic\AclManagerBundle\Acl\PermissionContextInterface;

interface AclManagerInterface {
    public function setPermission(PermissionContextInterface $permissionContext);
    
    public function processPermissions();
}

?>
