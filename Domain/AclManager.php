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
    /**
     * {@inheritDoc}
     */
    public function addObjectPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $mask, $securityIdentity, 'object', false);
    }
    
    /**
     * {@inheritDoc}
     */
    public function addClassPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $mask, $securityIdentity, 'class', false);
    }
    
    /**
     * @param mixed $domainObject
     * @param int   $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity
     * @param string $type
     * @param boolean $replace_existing
     * @return \Problematic\AclManagerBundle\Domain\AbstractAclManager 
     */
    protected function addPermission($domainObject, $mask, $securityIdentity = null, $type = 'object', $replace_existing = false)
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $context = $this->doCreatePermissionContext($type, $securityIdentity, $mask);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doApplyPermission($acl, $context, $replace_existing);
        
        $this->getAclProvider()->updateAcl($acl);
        
        return $this;
    }

    /**
     * @param mixed $domainObject
     * @param int   $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity
     * @param string $type
     * @param boolean $replace_existing
     * @return \Problematic\AclManagerBundle\Domain\AbstractAclManager 
     */
    protected function setPermission($domainObject, $mask, $securityIdentity = null, $type = 'object')
    {
        $this->addPermission($domainObject, $mask, $securityIdentity, $type, true);
        
        return $this;
    }
    /**
     * {@inheritDoc}
     */
    public function setObjectPermission($domainObject, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, $mask, $securityIdentity, 'object');
    }
    
    /**
     * {@inheritDoc}
     */
    public function setClassPermission($domainObject, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, $mask, $securityIdentity, 'class');
    }
    
    public function revokePermission($domainObject, $mask, $securityIdentity = null, $type = 'object')
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $context = $this->doCreatePermissionContext($type, $securityIdentity, $mask);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokePermission($acl, $context);
        $this->getAclProvider()->updateAcl($acl);
        
        return $this;
    }
    
    /**
     * {@inheritDoc}
     */
    public function revokeAllClassPermissions($domainObject, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $securityIdentity, 'class');
    }
    
    /**
     * {@inheritDoc}
     */
    public function revokeAllObjectPermissions($domainObject, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $securityIdentity, 'object');
    }
    
    protected function revokeAllPermissions($domainObject, $securityIdentity = null, $type = 'object')
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokeAllPermissions($acl, $securityIdentity, $type);
        $this->getAclProvider()->updateAcl($acl);
        
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
        
        return $acls;
    }
    
    public function deleteAclFor($domainObject)
    {
        $oid = ObjectIdentity::fromDomainObject($domainObject);
        $this->getAclProvider()->deleteAcl($oid);
        
        return $this;
    }

    public function isGranted($attributes, $object = null)
    {
        return $this->getSecurityContext()->isGranted($attributes, $object);
    }

    /**
     * {@inheritDoc}
     */
    public function getUser()
    {
        $token = $this->getSecurityContext()->getToken();

        if (null === $token) {
            return null;
        }

        $user = $token->getUser();

        return (is_object($user)) ? $user : 'IS_AUTHENTICATED_ANONYMOUSLY';
    }
    
}
