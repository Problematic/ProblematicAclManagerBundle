<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{
    /**
     * Sets permission mask for a given domain object. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     * 
     * @param mixed $domainObject 
     * @param int $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function addObjectPermission($domainObject, $mask, $securityIdentity = null);
    
    /**
     * Sets permission mask for a given class. All previous permissions for this
     * user and this class will be over written. If none existed, a new one will be created.
     * 
     * @param mixed $domainObject 
     * @param int $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function addClassPermission($domainObject, $mask, $securityIdentity = null);
    
    /**
     * Sets permission mask for a given domain object. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     * 
     * @param mixed $domainObject 
     * @param int $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function setObjectPermission($domainObject, $mask, $securityIdentity = null);
    
    /**
     * Sets permission mask for a given class. All previous permissions for this
     * user and this class will be over written. If none existed, a new one will be created.
     * 
     * @param mixed $domainObject 
     * @param int $mask
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function setClassPermission($domainObject, $mask, $securityIdentity = null);
    
    public function revokePermission($domainObject, $mask, $securityIdentity = null, $type = 'object');
    
    /**
     * @param mixed $domainObject
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllObjectPermissions($domainObject, $securityIdentity = null);
    
    /**
     * @param mixed $domainObject
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllClassPermissions($domainObject, $securityIdentity = null);
    
    public function deleteAclFor($domainObject);

    public function isGranted($attributes, $object = null);

    /**
     * Retrieves the current session user
     * 
     * @return UserInterface
     */
    public function getUser();

}
