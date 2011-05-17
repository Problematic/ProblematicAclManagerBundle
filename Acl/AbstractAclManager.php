<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Core\User\UserInterface;

use Problematic\AclManagerBundle\Acl\AclManagerInterface;
use Problematic\AclManagerBundle\Exception\InvalidIdentityException;
use Problematic\AclManagerBundle\Exception\AclNotLoadedException;

/**
 * abstract class containing low-level functionality (plumbing) to be extended by production AclManager (porcelain)
 */
abstract class AbstractAclManager {
    protected $securityContext;
    protected $aclProvider;
    protected $acl;
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) {
        $this->securityContext = $securityContext;
        $this->aclProvider = $aclProvider;
    }
    
    /**
     * Loads an ACL from the ACL provider, first by attempting to create, then finding if it already exists
     * 
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
        
        return $acl;
    }
    
    /**
     * Tells us whether we currently have an ACL currently loaded
     * 
     * @return boolean
     */
    protected function isAclLoaded() {
        return (null !== $this->acl) && $this->acl instanceof Acl;
    }
    
    /**
     * Wraps MutableAclProvider#updateAcl() to check if we currently have an ACL loaded
     * 
     * @throws AclNotLoadedException
     * @return void
     */
    protected function doUpdateAcl() {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before attempting to update it with the ACL provider");
        }
        
        $this->aclProvider->updateAcl($this->acl);
    }
    
    /**
     * Returns an instance of PermissionContext. If !$securityIdentity instanceof SecurityIdentityInterface, a new security identity will be created using it
     * 
     * @param string $type
     * @param $securityIdentity
     * @param integer $mask
     * @param boolean $granting
     * @return PermissionContext 
     */
    protected function doCreatePermissionContext($type, $securityIdentity, $mask, $granting = true) {
        if (!$securityIdentity instanceof SecurityIdentityInterface) {
            $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        }
        
        $permissionContext = new PermissionContext();
        $permissionContext->setPermissionType($type);
        $permissionContext->setSecurityIdentity($securityIdentity);
        $permissionContext->setPermissionMask($mask);
        $permissionContext->setGranting($granting);
        
        return $permissionContext;
    }
    
    /**
     * Creates a new object instanceof SecurityIdentityInterface from input implementing one of UserInterface, TokenInterface or RoleInterface
     * @param mixed $identity
     * @throws InvalidIdentityException
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
    
    /**
     * Loads an ACE collection from the ACL and updates the permissions (creating if no appropriate ACE exists)
     * 
     * @todo refactor this code to transactionalize ACL updating
     * @param PermissionContextInterface $context
     * @throws AclNotLoadedException
     * @return void
     */
    protected function doApplyPermission(PermissionContextInterface $context) {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before attempting to set permissions on it");
        }
        
        $type = $context->getPermissionType();
        
        $aceCollection = call_user_func(array($this->acl, "get{$type}Aces"));
        $aceFound = false;
        $doInsert = false;
        
        for ($i=count($aceCollection)-1; $i>=0; $i--) {
            if ($aceCollection[$i]->getSecurityIdentity() == $context->getSecurityIdentity()) {
                if ($aceCollection[$i]->isGranting() === $context->isGranting()) {
                    call_user_func(array($this->acl, "update{$type}Ace"), $i, $context->getPermissionMask());
                } else {
                    call_user_func(array($this->acl, "delete{$type}Ace"), $i);
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
    
    protected function doInstallDefaults() {
        if (!$this->isAclLoaded()) {
            throw new AclNotLoadedException("You must load a valid ACL before installing default permissions");
        }
        
        $builder = new MaskBuilder();
        $permissionContexts = array();
        
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_SUPER_ADMIN', MaskBuilder::MASK_IDDQD);
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_ADMIN', MaskBuilder::MASK_MASTER);
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'IS_AUTHENTICATED_ANONYMOUSLY', MaskBuilder::MASK_VIEW);
        
        $builder->add('VIEW');
        $builder->add('CREATE');
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_USER', $builder->get());
        
        foreach ($permissionContexts as $context) {
            $this->doApplyPermission($context);
        }
    }
}

?>
