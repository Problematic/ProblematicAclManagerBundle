<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;
use Problematic\AclManagerBundle\Model\AclManagerInterface;

/**
 * abstract class containing low-level functionality (plumbing) to be extended by production AclManager (porcelain)
 */
abstract class AbstractAclManager implements AclManagerInterface
{
    protected $securityContext;
    protected $aclProvider;
    
    public function __construct(SecurityContextInterface $securityContext, MutableAclProviderInterface $aclProvider) 
    {
        $this->securityContext = $securityContext;
        $this->aclProvider = $aclProvider;
    }
    
    /**
     * Loads an ACL from the ACL provider, first by attempting to create, then finding if it already exists
     * 
     * @param mixed $entity
     * @return MutableAclInterface
     */
    protected function doLoadAcl(ObjectIdentityInterface $objectIdentity) 
    {
        $acl = null;
        try {
            $acl = $this->aclProvider->createAcl($objectIdentity);
        } catch(AclAlreadyExistsException $ex) {
            $acl = $this->aclProvider->findAcl($objectIdentity);
        }
        
        return $acl;
    }
    
    protected function doRemoveAcl($token)
    {
        if (!$token instanceof ObjectIdentityInterface) {
            $token = ObjectIdentity::fromDomainObject($token);
        }
        
        $this->aclProvider->deleteAcl($token);
    }
    
    /**
     * Wraps MutableAclProvider#updateAcl() to check if we currently have an ACL loaded
     * 
     * @return void
     */
    protected function doUpdateAcl(MutableAclInterface $acl) 
    {
        $this->aclProvider->updateAcl($acl);
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
    protected function doCreatePermissionContext($type, $securityIdentity, $mask, $granting = true) 
    {
        if (!$securityIdentity instanceof SecurityIdentityInterface) {
            $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        }
        
        $permissionContext = new PermissionContext();
        $permissionContext->setPermissionType($type);
        $permissionContext->setSecurityIdentity($securityIdentity);
        $permissionContext->setMask($mask);
        $permissionContext->setGranting($granting);
        
        return $permissionContext;
    }
    
    /**
     * Creates a new object instanceof SecurityIdentityInterface from input implementing one of UserInterface, TokenInterface or RoleInterface (or its string representation)
     * @param mixed $identity
     * @throws InvalidIdentityException
     * @return SecurityIdentityInterface 
     */
    protected function doCreateSecurityIdentity($identity) 
    {

        if (!$identity instanceof UserInterface && !$identity instanceof TokenInterface && !$identity instanceof RoleInterface && !is_string($identity)) {
            throw new \InvalidArgumentException(sprintf('$identity must implement one of: UserInterface, TokenInterface, RoleInterface (%s given)', get_class($identity)));
        }
        
        $securityIdentity = null;
        if ($identity instanceof UserInterface) {
            $securityIdentity = UserSecurityIdentity::fromAccount($identity);
        } else if ($identity instanceof TokenInterface) {
            $securityIdentity = UserSecurityIdentity::fromToken($identity);
        } else if ($identity instanceof RoleInterface || is_string($identity)) {
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
     * @param MutableAclInterface $acl
     * @param PermissionContextInterface $context
     * @return void
     */
    protected function doApplyPermission(MutableAclInterface $acl, PermissionContextInterface $context) 
    {
        if (null === $context->getMask()) {
            // todo: delete the ACE
        }
        
        $type = $context->getPermissionType();
        $aceCollection = $this->getAceCollection($acl, $context);
        $aceFound = false;
        $doInsert = false;
        
        for ($i=count($aceCollection)-1; $i>=0; $i--) {
            if ($this->aceMatches($aceCollection[$i], $context)) {
                if ($this->aceMatches($aceCollection[$i], $context, array('granting'))) {
                    $acl->{"update{$type}Ace"}($i, $context->getMask());
                } else {
                    $acl->{"delete{$type}Ace"}($i);
                    $doInsert = true;
                }
                $aceFound = true;
            }
        }
        
        if ($doInsert || !$aceFound) {
            $acl->{"insert{$type}Ace"}($context->getSecurityIdentity(), $context->getMask(), 
                0, $context->isGranting());
        }
    }
    
    protected function doRemovePermission(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $type = $context->getPermissionType();
        $aceCollection = $this->getAceCollection($acl, $context);
        
        for ($i=count($aceCollection)-1; $i>=0; $i--) {
            if ($this->aceMatches($aceCollection[$i], $context, array('sid', 'perms'))) {
                $acl->{"delete{$type}Ace"}($i);
            }
        }
    }
    
    protected function doInstallDefaults(MutableAclInterface $acl) 
    {
        $builder = new MaskBuilder();
        $permissionContexts = array();
        
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_SUPER_ADMIN', MaskBuilder::MASK_IDDQD);
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_ADMIN', MaskBuilder::MASK_MASTER);
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'IS_AUTHENTICATED_ANONYMOUSLY', MaskBuilder::MASK_VIEW);
        
        $builder->add('VIEW');
        $builder->add('CREATE');
        $permissionContexts[] = $this->doCreatePermissionContext('class', 'ROLE_USER', $builder->get());
        
        foreach ($permissionContexts as $context) {
            $this->doApplyPermission($acl, $context);
        }
        
        $this->doUpdateAcl($acl);
    }
    
    private function aceMatches(AuditableEntryInterface $ace, PermissionContextInterface $context, array $checks = array())
    {
        if (empty($checks)) {
            $checks[] = 'sid';
        }
        
        $isMatch = false;
        if (in_array('sid', $checks)) {
            if ($ace->getSecurityIdentity() == $context->getSecurityIdentity()) {
                $isMatch = true;
            } else {
                return false;
            }
        }
        if (in_array('granting', $checks)) {
            if ($ace->isGranting() == $context->isGranting()) {
                $isMatch = true;
            } else {
                return false;
            }
        }
        if (in_array('perms', $checks)) {
            if ($ace->getMask() == $context->getMask() && $ace->isGranting() == $context->isGranting()) {
                $isMatch = true;
            } else {
                return false;
            }
        }
        
        return $isMatch;
    }
    
    private function getAceCollection(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $aceCollection = $acl->{"get{$context->getPermissionType()}Aces"}();
        
        return $aceCollection;
    }
}
