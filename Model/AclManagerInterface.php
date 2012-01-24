<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{

    public function addPermission($domainObject, $mask, $securityIdentity = null, $type = 'object');
    
    public function setPermission($domainObject, $mask, $securityIdentity = null, $type = 'object');
    
    public function revokePermission($domainObject, $mask, $securityIdentity = null, $type = 'object');
    
    public function deleteAclFor($domainObject);

    public function isGranted($attributes, $object = null);

    public function getUser();

}
