<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

interface PermissionContextInterface {
    public function setPermissionMask($mask);
    public function getPermissionMask();
    
    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity);
    public function getSecurityIdentity();
    
    public function setPermissionType($type);
    public function getPermissionType();
    
    public function setGranting($granting);
    public function isGranting();
}

?>
