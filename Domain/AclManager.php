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
use Symfony\Component\Security\Acl\Exception\NoAceFoundException;

class AclManager extends AbstractAclManager
{
    /**
     * {@inheritDoc}
     */
    public function addObjectPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, null,  $mask, $securityIdentity, 'object', false);
    }

    /**
     * {@inheritDoc}
     */
    public function addClassPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, null, $mask, $securityIdentity, 'class', false);
    }

    /**
     * {@inheritDoc}
     */
    public function addObjectFieldPermission($domainObject, $field, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $field, $mask, $securityIdentity, 'object', false);
    }

    /**
     * {@inheritDoc}
     */
    public function addClassFieldPermission($domainObject, $field, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $field, $mask, $securityIdentity, 'class', false);
    }

    /**
     * @param mixed $domainObject
     * @param string $field
     * @param int   $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity
     * @param string $type
     * @param string $field
     * @param boolean $replace_existing
     * @return \Problematic\AclManagerBundle\Domain\AbstractAclManager
     */
    protected function addPermission($domainObject, $field, $mask, $securityIdentity = null, $type = 'object', $replace_existing = false)
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $context = $this->doCreatePermissionContext($type, $field, $securityIdentity, $mask);
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($domainObject);
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
     * @param string $field
     * @return \Problematic\AclManagerBundle\Domain\AbstractAclManager
     */
    protected function setPermission($domainObject, $field, $mask, $securityIdentity = null, $type = 'object')
    {
        $this->addPermission($domainObject, $field, $mask, $securityIdentity, $type, true);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function setObjectPermission($domainObject, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, null, $mask, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function setClassPermission($domainObject, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, null, $mask, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function setObjectFieldPermission($domainObject, $field, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, $field, $mask, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function setClassFieldPermission($domainObject, $field, $mask, $securityIdentity = null){
        $this->setPermission($domainObject, $field, $mask, $securityIdentity, 'class');
    }

    public function revokePermission($domainObject, $mask, $securityIdentity = null, $type = 'object')
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $context = $this->doCreatePermissionContext($type, null, $securityIdentity, $mask);
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokePermission($acl, $context);
        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    public function revokeFieldPermission($domainObject, $field, $mask, $securityIdentity = null, $type = 'object')
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $context = $this->doCreatePermissionContext($type, $field, $securityIdentity, $mask);
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($domainObject);
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
        $this->revokeAllPermissions($domainObject, null, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllObjectPermissions($domainObject, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, null, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllClassFieldPermissions($domainObject, $field, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $field, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllObjectFieldPermissions($domainObject, $field, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $field, $securityIdentity, 'object');
    }
    protected function revokeAllPermissions($domainObject, $field, $securityIdentity = null, $type = 'object')
    {
        if(is_null($securityIdentity)){
            $securityIdentity = $this->getUser();
        }
        $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($domainObject);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokeAllPermissions($acl, $securityIdentity, $type, $field);
        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    public function preloadAcls($objects, $identities = array())
    {
        $oids = array();
        foreach ($objects as $object) {
            $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($object);
            $oids[] = $oid;
        }

        $sids = array();
        foreach ($identities as $identity) {
            $sid = $this->doCreateSecurityIdentity($identity);
            $sids[] = $sid;
        }

        $acls = $this->getAclProvider()->findAcls($oids, $sids); // todo: do we need to do anything with these?

        return $acls;
    }

    public function deleteAclFor($domainObject)
    {
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($domainObject);
        $this->getAclProvider()->deleteAcl($oid);

        return $this;
    }

    public function isGranted($attributes, $object = null)
    {
        return $this->getSecurityContext()->isGranted($attributes, $object);
    }

    public function isFieldGranted($masks, $object, $field)
    {
        $oid = $this->getObjectIdentityRetrievalStrategy()->getObjectIdentity($object);
        $acl = $this->doLoadAcl($oid);

        try {
            return $acl->isFieldGranted($field, $masks, array(
                $this->doCreateSecurityIdentity( $this->getUser() )
            ));
        } catch (NoAceFoundException $ex) {
            return false;
        }
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
