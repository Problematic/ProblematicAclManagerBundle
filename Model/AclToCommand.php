<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Domain\ObjectIdentity;

class AclToCommand extends AclCommand
{
    
    public function on($entity)
    {
        $oid = ObjectIdentity::fromDomainObject($entity);
        $this->getContext()->setObjectIdentity($oid);
        
        return new AclOnCommand($this->getContext(), $this->getAclManager());
    }

}
