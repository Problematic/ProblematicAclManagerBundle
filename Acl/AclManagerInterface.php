<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

interface AclManagerInterface {
    public function loadAcl($entity = null);
    public function updateAcl();
    
    public function createSecurityIdentity($identity);
    
    public function createPermissionContext(SecurityIdentityInterface $securityIdentity, array $args);
    public function addPermissionContext(PermissionContextInterface $permissionContext, $key = null);
    public function processPermissions($reset = false);
    public function applyPermission(PermissionContextInterface $permissionContext);
}

?>
