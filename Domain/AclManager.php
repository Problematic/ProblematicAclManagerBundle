<?php

namespace Problematic\AclManagerBundle\Domain;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Core\SecurityContext;
use Problematic\AclManagerBundle\Model\AclManagerInterface;
use Problematic\AclManagerBundle\Domain\AbstractAclManager;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Problematic\AclManagerBundle\Model\AclAccessCommand;
use Problematic\AclManagerBundle\Model\AclCommandContext;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;

class AclManager extends AbstractAclManager 
{
    
    public function permit($identity)
    {
        return new AclAccessCommand('permit', $commandContext, $this);
    }
    
    public function deny($identity)
    {
        return $this->createAccessCommand('deny', $identity);
    }
    
    public function loadAcl($oid)
    {
        return $this->doLoadAcl($oid);
    }
    
    public function addPermission(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $this->doApplyPermission($acl, $context);
        
        return $this;
    }
    
    public function revokePermission(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $this->doRevokePermission($acl, $context);
        
        return $this;
    }
    
    public function revokeAllPermissions(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $this->doRevokeAllPermissions($acl, $context->getSecurityIdentity(), 'object');
        
        return $this;
    }
    
    public function preloadAcls($objects)
    {
        $oids = array();
        foreach ($objects as $object) {
            $oid = ObjectIdentity::fromDomainObject($object);
            $oids[] = $oid;
        }
        
        $acls = $this->getAclProvider()->findAcls($oids); // todo: do we need to do anything with these?
        
        return $this;
    }
    
    public function deleteAclFor($domainObject)
    {
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $this->getAclProvider()->deleteAcl($oid);
        
        return $this;
    }
    
    private function createAccessCommand($access_type, $identity)
    {
        $commandContext = new AclCommandContext();
        $identity = $this->doCreateSecurityIdentity($identity);
        $commandContext->setSecurityIdentity($identity);
        
        return new AclAccessCommand($access_type, $commandContext, $this);
    }
    
}
