<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\SecurityContext;

class AclManager extends AbstractAclManager {
    protected $maskBuilder;
    protected $entityContext;
    protected $permissionContextCollection = array();
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) {
        parent::__construct($securityContext, $aclProvider);
        
        $this->maskBuilder = new MaskBuilder();
    }
    
    public function hasEntityContext() {
        return (null !== $this->entityContext) && is_object($this->entityContext);
    }
    public function setEntityContext($entity) {
        $this->entityContext = $entity;
        
        return $this;
    }
    
    public function processPermissions($reset = false) {
        foreach ($this->permissionContextCollection as $permissionContext) {
            $this->setPermission($permissionContext);
        }
        $this->updateAcl();
        
        if ($reset) {
            $this->permissionContextCollection = array();
        }
        
        return $this;
    }
    
    public function createPermissionContext($type, SecurityIdentityInterface $securityIdentity, $mask) {
        return $this->doCreatePermissionContext($type, $securityIdentity, $mask);
    }
    public function addPermissionContext(PermissionContextInterface $permissionContext, $key = null) {
        if (null === $key) {
            $this->permissionContextCollection[] = $permissionContext;
        } else {
            $this->permissionContextCollection[$key] = $permissionContext;
        }
    }
    public function getPermissionContextCollection() {
        return $this->permissionContextCollection;
    }
    public function getPermissionContext($key) {
        return $this->permissionContextCollection[$key];
    }
    
    public function createSecurityIdentity($identity) {
        return $this->doCreateSecurityIdentity($identity);
    }
    
    public function loadAcl($entityContext = null) {
        if ((null === $entityContext) && !$this->hasEntityContext()) {
            throw new Exception("Set an entity context before trying to load an ACL");
        }
        $entityContext = $entityContext ?: $this->entityContext;
        $this->doLoadAcl($entityContext);
        
        return $this;
    }
    
    public function updateAcl() {
        $this->doUpdateAcl();
        
        return $this;
    }
    
    public function installDefaultAccess() {
        $this->doInstallDefaultAccess($this->entityContext);
        
        return $this;
    }
    
    public function setPermission(PermissionContextInterface $permissionContext) {
        $this->doSetPermission($permissionContext);
        
        return $this;
    }
    
    /**
     * @return MaskBuilder
     */
    public function getMaskBuilder() {
        return $this->maskBuilder->reset();
    }
}

?>