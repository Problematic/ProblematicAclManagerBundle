<?php

namespace Problematic\AclManagerBundle\Acl;

use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Config\Definition\Exception\InvalidTypeException;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;

use Problematic\AclManagerBundle\Exception\InvalidIdentityException;

class AclManager {
    protected $securityContext;
    protected $aclProvider;
    protected $maskBuilder;
    
    /**
     * @var Acl
     */
    protected $acl;
    protected $securityIdentity;
    
    public function __construct(SecurityContext $securityContext, MutableAclProvider $aclProvider) {
        $this->securityContext = $securityContext;
        $this->aclProvider = $aclProvider;
        $this->maskBuilder = new MaskBuilder();
    }
    
    /**
     * @param mixed $entity
     * @return AclManager 
     */
    public function loadAcl($entity) {
        $this->acl = $this->doLoadAcl($entity);
        
        return $this;
    }
    
    /**
     * @param mixed $entity
     * @return Acl
     */
    public function doLoadAcl($entity) {
        $objectIdentity = ObjectIdentity::fromDomainObject($entity);
        
        try {
            $acl = $this->aclProvider->createAcl($objectIdentity);
        } catch(AclAlreadyExistsException $ex) {
            $acl = $this->aclProvider->findAcl($objectIdentity);
        }
        
        return $acl;
    }
    
    /**
     * @param mixed $identity
     * @return AclManager 
     */
    public function createSecurityIdentity($identity) {
        $this->securityIdentity = $this->doCreateSecurityIdentity($identity);

        return $this;
    }
    
    /**
     * @param mixed $identity
     * @return SecurityIdentityInterface 
     */
    protected function doCreateSecurityIdentity($identity) {
        if( is_string($identity)) {
            $identity = new Role($identity);
        }

        if( !($identity instanceof UserInterface) && !($identity instanceof TokenInterface) && !($identity instanceof RoleInterface) ) {
            throw new InvalidIdentityException('$identity must implement one of: UserInterface, TokenInterface, RoleInterface (' . get_class($identity) . ' given)');
        }
        
        $securityIdentity = null;
        if( $identity instanceof UserInterface ) {
            $securityIdentity = UserSecurityIdentity::fromAccount($identity);
        } else if( $identity instanceof TokenInterface ) {
            $securityIdentity = UserSecurityIdentity::fromToken($identity);
        } else if( $identity instanceof RoleInterface ) {
            $securityIdentity = new RoleSecurityIdentity($identity);
        }

        if( null === $securityIdentity || !($securityIdentity instanceof SecurityIdentityInterface) ) {
            throw new InvalidIdentityException('Couldn\'t create a valid SecurityIdentity with the provided identity information');
        }
        
        return $securityIdentity;
    }
    
    /**
     * @param integer $mask
     * @return AclManager 
     */
    public function grantPermission($mask) {
        $this->doSetPermission($mask, $this->acl, $this->securityIdentity);
        
        return $this;
    }
    
    /**
     * @param integer $mask
     * @return AclManager 
     */
    public function denyPermission($mask) {
        $this->doSetPermission($mask, $this->acl, $this->securityIdentity, false);
        
        return $this;
    }
    
    /**
     * @param integer $mask
     * @param Acl $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param boolean $granting
     * @param integer $index 
     */
    protected function doSetPermission($mask, Acl $acl, SecurityIdentityInterface $securityIdentity, $granting = true, $index = 0) {
        if (!is_integer($mask)) {
            throw new InvalidTypeException('$mask must be an integer');
        }
        
        $objectAces = $acl->getObjectAces();
        $classAces = $acl->getClassAces();
        
        $acl->insertObjectAce($securityIdentity, $mask, $index, $granting);
        $this->aclProvider->updateAcl($acl);
    }
    
    /**
     * @param mixed $entity 
     */
    public function installDefaultAccess($entity) {
        $this->doInstallDefaultAccess($entity);
        
        return $this;
    }
    
    protected function doInstallDefaultAccess($entity) {
        $acl = $this->doLoadAcl($entity);
        
        $builder = $this->maskBuilder->reset();

        $builder->add('iddqd');
        $acl->insertClassAce(new RoleSecurityIdentity('ROLE_SUPER_ADMIN'), $builder->get());

        $builder->reset();
        $builder->add('master');
        $acl->insertClassAce(new RoleSecurityIdentity('ROLE_ADMIN'), $builder->get());

        $builder->reset();
        $builder->add('view');
        $acl->insertClassAce(new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'), $builder->get());

        $builder->reset();
        $builder->add('create');
        $builder->add('view');
        $acl->insertClassAce(new RoleSecurityIdentity('ROLE_USER'), $builder->get());
        
        $this->aclProvider->updateAcl($acl);
        
        return true;
    }
    
    /**
     * @return MaskBuilder
     */
    public function getMaskBuilder() {
        return $this->maskBuilder;
    }
    
    /**
     * @return Acl
     */
    public function getAcl() {
        return $this->acl;
    }
    
    /**
     * @return SecurityIdentity
     */
    public function getSecurityIdentity() {
        return $this->securityIdentity;
    }
}

?>
