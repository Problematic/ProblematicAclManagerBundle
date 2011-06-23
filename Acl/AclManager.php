<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Core\SecurityContext;

use Problematic\AclManagerBundle\Acl\AbstractAclManager;
use Problematic\AclManagerBundle\Acl\PermissionContextInterface;
use Problematic\AclManagerBundle\Exception\AclNotLoadedException;

class AclManager extends AbstractAclManager 
{
    protected $permissionContextCollection = array();
    protected $acl;
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) 
    {
        parent::__construct($securityContext, $aclProvider);
    }
    
    /**
     * Tells us whether we currently have an ACL currently loaded
     * 
     * @return boolean
     */
    protected function isAclLoaded() 
    {
        return (null !== $this->acl) && $this->acl instanceof Acl;
    }
    
    public function processPermissions($reset = false) 
    {
        foreach ($this->permissionContextCollection as $permissionContext) {
            $this->applyPermission($permissionContext);
        }
        $this->updateAcl();
        
        if ($reset) {
            $this->permissionContextCollection = array();
        }
        
        return $this;
    }
    
    public function createPermissionContext($type, $securityIdentity, $mask, $granting = true) 
    {
        return $this->doCreatePermissionContext($type, $securityIdentity, $mask, $granting);
    }
    
    public function addPermissionContext(PermissionContextInterface $permissionContext, $key = null) 
    {
        if (null === $key) {
            $this->permissionContextCollection[] = $permissionContext;
        } else {
            $this->permissionContextCollection[$key] = $permissionContext;
        }
        
        return $this;
    }
    
    public function createSecurityIdentity($identity) 
    {
        return $this->doCreateSecurityIdentity($identity);
    }
    
    public function loadAcl($entity) 
    {
        if (null === $entity || !is_object($entity)) {
            throw new Exception("Provide a valid entity context before trying to load an ACL");
        }
        $this->acl = $this->doLoadAcl($entity);
        
        return $this;
    }
    
    public function updateAcl() 
    {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before attempting to update it with the ACL provider");
        }
        
        $this->doUpdateAcl($this->acl);
        
        return $this;
    }
    
    public function applyPermission(PermissionContextInterface $permissionContext) 
    {
        $this->doApplyPermission($this->acl, $permissionContext);
        
        return $this;
    }
    
    public function installDefaults() 
    {
        $this->doInstallDefaults($this->acl);
        
        return $this;
    }
}
