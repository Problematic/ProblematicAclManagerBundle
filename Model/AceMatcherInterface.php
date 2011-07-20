<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;

interface AceMatcherInterface
{
    
    public function setAce(AuditableEntryInterface $ace);
    
    /**
     * @return AuditableEntryInterface
     */
    public function getAce();
    
    public function setContext(PermissionContextInterface $context);
    
    /**
     * @return PermissionContextInterface
     */
    public function getContext();
    
    /**
     * @return boolean
     */
    public function permissionsMatch(AuditableEntryInterface $ace = null, PermissionContextInterface $context = null);

}
