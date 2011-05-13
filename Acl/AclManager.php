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
    
//    /**
//     * @param integer $mask
//     * @return AclManager 
//     */
//    public function grantPermission($mask) {
//        $this->doSetPermission($mask, $this->acl, $this->securityIdentity);
//        
//        return $this;
//    }
    
//    /**
//     * @param integer $mask
//     * @return AclManager 
//     */
//    public function denyPermission($mask) {
//        $this->doSetPermission($mask, $this->acl, $this->securityIdentity, false);
//        
//        return $this;
//    }
    
//    /**
//     * @param integer $mask
//     * @param Acl $acl
//     * @param SecurityIdentityInterface $securityIdentity
//     * @param boolean $granting
//     * @param integer $index 
//     */
//    protected function doSetPermission($mask, Acl $acl, SecurityIdentityInterface $securityIdentity, $granting = true, $index = 0) {
//        if (!is_integer($mask)) {
//            throw new InvalidTypeException('$mask must be an integer');
//        }
//        
//        $acl->insertObjectAce($securityIdentity, $mask, $index, $granting);
//        $this->aclProvider->updateAcl($acl);
//    }
    
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
     * @param integer $mask
     * @return AclManager 
     */
    public function setObjectPermission($mask) {
        $this->doSetObjectPermission($mask, $this->acl, $this->securityIdentity);
        
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
        $objectAces = $acl->getObjectAces();
        
        $this->doSetPermission('objectAce', $objectAces, array(
            'mask'              => $mask,
            'acl'               => $acl,
            'securityIdentity'  => $securityIdentity,
            'granting'          => $granting,
            'index'             => $index,
        ));
    }
    
    protected function doSetPermission($type, $aceCollection, array $args) {
        $defaults = array(
            'mask'              => 0,
            'acl'               => null,
            'securityIdentity'  => null,
            'granting'          => true,
            'index'             => 0,
        );
        $settings = array_merge($defaults, $args);
        $preppedType = ucfirst($settings);
        
        $aceFound = false;
        foreach ($aceCollection as $index=>$ace) {
            if (($ace->getSecurityIdentity() === $settings['securityIdentity']) && ($ace->getMask() === $settings['mask'])) {
                if ($ace->isGranting() === $settings['granting']) {
                    call_user_func(array($settings['acl'], "update{$preppedType}"), 
                            $settings['index'], $settings['mask']);
//                    $acl->updateClassAce($index, $mask);
                } else {
                    call_user_func(array($settings['acl'], "delete{$preppedType}"), 
                            $settings['index']);
//                    $acl->deleteClassAce($index);
                    call_user_func(array($settings['acl'], "insert{$preppedType}"), 
                            $settings['securityIdentity'], $settings['mask'], $settings['index'], $settings['granting']);
//                    $acl->insertClassAce($securityIdentity, $mask, $index, $granting);
                }
                $aceFound = true;
            }
        }
        
        if (!$aceFound) {
            call_user_func(array($settings['acl'], "insert{$preppedType}"),
                    $settings['securityIdentity'], $settings['mask'], $settings['index'], $settings['granting']);
//            $acl->insertClassAce($securityIdentity, $mask, $index, $granting);
        }
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
     * @param type $mask
     * @param Acl $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param type $granting
     * @param type $index 
     */
    protected function doSetClassPermission($mask, Acl $acl, SecurityIdentityInterface $securityIdentity, $granting = true, $index = 0) {
        $classAces = $acl->getClassAces();
        
        $this->doSetPermission('classAce', $classAces, array(
            'mask'              => $mask,
            'acl'               => $acl,
            'securityIdentity'  => $securityIdentity,
            'granting'          => $granting,
            'index'             => $index,
        ));
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
