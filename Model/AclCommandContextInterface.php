<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

interface AclCommandContextInterface
{
    
    function setObjectIdentity(ObjectIdentityInterface $oid);
    function getObjectIdentity();
    
    function setSecurityIdentity(SecurityIdentityInterface $sid);
    function getSecurityIdentity();
    
    function setMask($mask);
    function getMask();
    
    function setAccessType($access_type);
    function getAccessType();
    
    function setPermissionType($permission_type);
    function getPermissionType();

}
