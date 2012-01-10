<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{

    public function addPermission($domainObject, $securityIdentity, $mask, $type = 'object', $installDefaults = true);
    
    public function revokePermission($domainObject, $securityIdentity, $mask, $type = 'object');
    
    public function deleteAclFor($domainObject);

    public function isGranted($attributes, $object = null);

    public function getUser();

}
