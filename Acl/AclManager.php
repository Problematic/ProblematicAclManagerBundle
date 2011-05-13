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
     * @param mixed $entity 
     */
    public function installDefaultAccess($entity) {
        $this->doInstallDefaultAccess($entity);
        
        return $this;
    }
    
    protected function doInstallDefaultAccess($entity) {
        $acl = $this->doLoadAcl($entity);
        
        $builder = $this->getMaskBuilder();

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
     * @param integer $mask
     * @return AclManager 
     */
    public function setObjectPermission($mask) {
        $this->doSetObjectPermission($mask, $this->acl, $this->securityIdentity);
        
        return $this;
    }
    
    /**
     * @param integer $mask
     * @return AclManager 
     */
    public function setClassPermission($mask) {
        $this->doSetClassPermission($mask, $this->acl, $this->securityIdentity);
        
        return $this;
    }
    
    /**
     * @param integer $mask
     * @param Acl $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param boolean $granting
     * @param integer $index 
     */
    protected function doSetObjectPermission($mask, Acl $acl, SecurityIdentityInterface $securityIdentity, $granting = true, $index = 0) {
        $this->doSetPermission('object', $acl, array(
            'mask'              => $mask,
            'securityIdentity'  => $securityIdentity,
            'granting'          => $granting,
            'index'             => $index,
        ));
    }
    
    /**
     * @param type $mask
     * @param Acl $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param type $granting
     * @param type $index 
     */
    protected function doSetClassPermission($mask, Acl $acl, SecurityIdentityInterface $securityIdentity, $granting = true, $index = 0) {
        $this->doSetPermission('class', $acl, array(
            'mask'              => $mask,
            'securityIdentity'  => $securityIdentity,
            'granting'          => $granting,
            'index'             => $index,
        ));
    }
    
    /**
     * Takes an ACE type (class/object), an ACL and an array of settings (mask, identity, granting, index)
     * Loads an ACE collection from the ACL and updates the permissions (creating if no appropriate ACE exists)
     * 
     * @param string $type
     * @param array $aceCollection
     * @param array $args 
     */
    protected function doSetPermission($type, Acl $acl, array $args) {
        $defaults = array(
            'mask'              => 0,
            'securityIdentity'  => null,
            'granting'          => true,
            'index'             => 0,
        );
        $settings = array_merge($defaults, $args);
        
        $aceCollection = call_user_func(array($acl, "get{$type}Aces"));
        $aceFound = false;
        
        //we iterate backwards because removing an ACE reorders everything after it, which will cause unexpected results when iterating forward
        for ($i=count($aceCollection)-1; $i>=0; $i--) {
            if (($aceCollection[$i]->getSecurityIdentity() === $settings['securityIdentity']) && ($aceCollection[$i]->getMask() === $settings['mask'])) {
                if ($aceCollection[$i]->isGranting() === $settings['granting']) {
                    call_user_func(array($acl, "update{$type}Ace"), 
                            $i, $settings['mask']);
                } else {
                    call_user_func(array($acl, "delete{$type}Ace"), 
                            $i);
                    call_user_func(array($acl, "insert{$type}Ace"), 
                            $settings['securityIdentity'], $settings['mask'], $settings['index'], $settings['granting']);
                }
                $aceFound = true;
            }
        }
        
        if (!$aceFound) {
            call_user_func(array($acl, "insert{$type}Ace"),
                    $settings['securityIdentity'], $settings['mask'], $settings['index'], $settings['granting']);
        }
    }
    
    /**
     * @return MaskBuilder
     */
    public function getMaskBuilder() {
        return $this->maskBuilder->reset();
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
