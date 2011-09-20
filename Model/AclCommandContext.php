<?php

namespace Problematic\AclManagerBundle\Model;

class AclCommandContext implements AclCommandContextInterface
{
    
    private $oid;
    private $sid;
    private $mask;
    private $access_type;
    private $permission_type;
    
    public function setObjectIdentity(ObjectIdentityInterface $oid)
    {
        $this->oid = $oid;
    }
    
    public function getObjectIdentity()
    {
        return $this->oid;
    }
    
    public function setSecurityIdentity(SecurityIdentityInterface $sid)
    {
        $this->sid = $sid;
    }
    
    public function getSecurityIdentity()
    {
        return $this->sid;
    }
    
    public function setMask($mask)
    {
        $this->mask = $mask;
    }
    
    public function getMask()
    {
        return $this->mask;
    }
    
    public function setAccessType($access_type)
    {
        $this->access_type = $access_type;
    }
    
    public function getAccessType()
    {
        return $this->access_type;
    }
    
    public function setPermissionType($permission_type)
    {
        $this->permission_type = $permission_type;
    }
    
    public function getPermissionType()
    {
        return $this->permission_type;
    }

}
