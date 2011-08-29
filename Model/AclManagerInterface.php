<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{

    public function add($domainObject, $securityIdentity, $mask, $type = 'object', $installDefaults = true);
    
    public function delete($domainObject);
}
