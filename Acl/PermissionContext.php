<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

use Problematic\AclManagerBundle\Acl\PermissionContextInterface;

class PermissionContext implements PermissionContextInterface {
    protected $permissionMask;
    protected $securityIdentity;
    
    public function __construct() {}
    
    public function setPermissionMask($mask) {
        $this->permissionMask = $mask;
    }
    public function getPermissionMask() {
        return $this->permissionMask;
    }
    
    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity) {
        $this->securityIdentity = $securityIdentity;
    }
    public function getSecurityIdentity() {
        return $this->securityIdentity;
    }
}

?>
