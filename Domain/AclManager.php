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

class AclManager extends AbstractAclManager 
{
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) 
    {
        parent::__construct($securityContext, $aclProvider);
    }
    
    public function addPermission($domainObject, $securityIdentity, $mask, $type = 'object', $installDefaults = true)
    {
        $context = $this->doCreatePermissionContext($type, $securityIdentity, $mask);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doApplyPermission($acl, $context);
        
        if ($installDefaults) {
            $this->doInstallDefaults($acl);
        }
        
        $this->aclProvider->updateAcl($acl);
        
        return $this;
    }
    
    public function deleteAclFor($domainObject)
    {
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $this->aclProvider->deleteAcl($oid);
        
        return $this;
    }
    
    public function revokePermission($domainObject, $securityIdentity, $mask, $type = 'object')
    {
        $context = $this->doCreatePermissionContext($type, $securityIdentity, $mask);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokePermission($acl, $context);
        $this->aclProvider->updateAcl($acl);
        
        return $this;
    }
    
    public function revokeAllPermissions($domainObject, $securityIdentity, $type = 'object')
    {
        $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokeAllPermissions($acl, $securityIdentity, $type);
        $this->aclProvider->updateAcl($acl);
        
        return $this;
    }
    
}
