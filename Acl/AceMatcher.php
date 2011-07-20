<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;

class AceMatcher extends AbstractAceMatcher
{
    
    public function permissionsMatch(AuditableEntryInterface $ace = null, PermissionContextInterface $context = null)
    {
        $ace = $ace ?: $this->getAce();
        $context = $context ?: $this->getContext();
        
        return $ace()->getSecurityIdentity() == $context()->getSecurityIdentity()
            && $ace()->isGranting() == $context()->isGranting()
            && $ace()->getMask() == $context()->getMask();
    }

}
