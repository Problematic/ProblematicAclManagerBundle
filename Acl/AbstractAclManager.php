<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Core\User\UserInterface;

use Problematic\AclManagerBundle\Acl\AclManagerInterface;
use Problematic\AclManagerBundle\Exception\InvalidIdentityException;
use Problematic\AclManagerBundle\Exception\AclNotLoadedException;

/**
 * Low-level functionality to be extended by production AclManager
 */
abstract class AbstractAclManager implements AclManagerInterface {
    protected $securityContext;
    protected $aclProvider;
    protected $acl;
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) {
        $this->securityContext = $securityContext;
        $this->aclProvider = $aclProvider;
    }
    
        /**
     * @param mixed $entity
     * @return Acl
     */
    protected function doLoadAcl($entity) {
        $objectIdentity = ObjectIdentity::fromDomainObject($entity);
        
        // is this faster than finding, and creating on null?
        try {
            $acl = $this->aclProvider->createAcl($objectIdentity);
        } catch(AclAlreadyExistsException $ex) {
            $acl = $this->aclProvider->findAcl($objectIdentity);
        }
        
        $this->acl = $acl;
        
        return true;
    }
    
    protected function isAclLoaded() {
        return (null !== $this->acl) && $this->acl instanceof Acl;
    }
    
    protected function doUpdateAcl() {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before attempting to update it with the ACL provider");
        }
        
        $this->aclProvider->updateAcl($this->acl);
    }
    
    /**
     * @param SecurityIdentityInterface $securityIdentity
     * @param integer $mask
     * @return PermissionContext 
     */
    protected function doCreatePermissionContext($type, SecurityIdentityInterface $securityIdentity, $mask) {
        $permissionContext = new PermissionContext();
        $permissionContext->setSecurityIdentity($securityIdentity);
        $permissionContext->setPermissionMask($mask);
        $permissionContext->setPermissionType($type);
        
        return $permissionContext;
    }
    
    /**
     * @param mixed $identity
     * @return SecurityIdentityInterface 
     */
    protected function doCreateSecurityIdentity($identity) {
        if (is_string($identity)) {
            $identity = new Role($identity);
        }

        if (!($identity instanceof UserInterface) && !($identity instanceof TokenInterface) && !($identity instanceof RoleInterface)) {
            throw new InvalidIdentityException('$identity must implement one of: UserInterface, TokenInterface, RoleInterface (' . get_class($identity) . ' given)');
        }
        
        $securityIdentity = null;
        if ($identity instanceof UserInterface) {
            $securityIdentity = UserSecurityIdentity::fromAccount($identity);
        } else if ($identity instanceof TokenInterface) {
            $securityIdentity = UserSecurityIdentity::fromToken($identity);
        } else if ($identity instanceof RoleInterface) {
            $securityIdentity = new RoleSecurityIdentity($identity);
        }

        if (null === $securityIdentity || !($securityIdentity instanceof SecurityIdentityInterface)) {
            throw new InvalidIdentityException('Couldn\'t create a valid SecurityIdentity with the provided identity information');
        }
        
        return $securityIdentity;
    }
    
    protected function doInstallDefaultAccess($entity) {
        $acl = $this->doLoadAcl($entity);
        
        $builder = $this->getMaskBuilder();

        $builder->add('iddqd');
        $this->doSetPermission('class', $acl, array(
            'mask'              => $builder->get(),
            'securityIdentity'  => new RoleSecurityIdentity('ROLE_SUPER_ADMIN'),
        ));

        $builder->reset();
        $builder->add('master');
        $this->doSetPermission('class', $acl, array(
            'mask'              => $builder->get(),
            'securityIdentity'  => new RoleSecurityIdentity('ROLE_ADMIN'),
        ));

        $builder->reset();
        $builder->add('view');
        $this->doSetPermission('class', $acl, array(
            'mask'              => $builder->get(),
            'securityIdentity'  => new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
        ));

        $builder->reset();
        $builder->add('create');
        $builder->add('view');
        $this->doSetPermission('class', $acl, array(
            'mask'              => $builder->get(),
            'securityIdentity'  => new RoleSecurityIdentity('ROLE_USER'),
        ));
        
        return true;
    }
    
    /**
     * Takes an ACE type (class/object), an ACL and an array of settings (mask, identity, granting, index)
     * Loads an ACE collection from the ACL and updates the permissions (creating if no appropriate ACE exists)
     * 
     * @todo refactor this code to transactionalize ACL updating
     * 
     * @param PermissionContextInterface $context
     */
    protected function doSetPermission(PermissionContextInterface $context) {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before attempting to set permissions on it");
        }
        
        $type = $context->getPermissionType();
        
        $aceCollection = call_user_func(array($this->acl, "get{$type}Aces"));
        $aceFound = false;
        $doInsert = false;
        
        for ($i=count($aceCollection)-1; $i>=0; $i--) {
            if ($aceCollection[$i]->getSecurityIdentity() === $context->getSecurityIdentity()) {
                if ($aceCollection[$i]->isGranting() === $context->isGranting()) {
                    call_user_func(array($this->acl, "update{$type}Ace"), $i, $context->getPermissionMask());
                } else {
                    call_use_func(array($this->acl, "delete{$type}Ace"), $i);
                    $doInsert = true;
                }
                $aceFound = true;
            }
        }
        
        if ($doInsert || !$aceFound) {
            call_user_func(array($this->acl, "insert{$type}Ace"),
                    $context->getSecurityIdentity(), $context->getPermissionMask(), 0, $context->isGranting());
        }
    }
}

?>
