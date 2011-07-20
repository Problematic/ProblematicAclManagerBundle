<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;

class PermissionContext implements PermissionContextInterface
{

    protected $permissionMask;
    protected $securityIdentity;
    protected $permissionType;
    protected $granting;

    public function __construct()
    {
        
    }

    public function setMask($mask)
    {
        $this->permissionMask = $mask;
    }

    public function getMask()
    {
        return $this->permissionMask;
    }

    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity)
    {
        $this->securityIdentity = $securityIdentity;
    }

    public function getSecurityIdentity()
    {
        return $this->securityIdentity;
    }

    public function setPermissionType($type)
    {
        $this->permissionType = $type;
    }

    public function getPermissionType()
    {
        return $this->permissionType;
    }

    public function setGranting($granting)
    {
        $this->granting = $granting;
    }

    public function isGranting()
    {
        return $this->granting;
    }

}

?>
