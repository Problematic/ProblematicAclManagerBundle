<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{

    public function addPermission($domainObject, $securityIdentity, $mask, $type = 'object', $installDefaults = true);
    
    public function deleteAcl($domainObject);
}
