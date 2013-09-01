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

    /** Set permission mask for a given field of a domain object. All previous permissions
     * for this user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed $domainObject
     * @param string $field
     * @param int $mask
     * @param UserInterface | ToekInterface | RoleInterface $securityIdentity if none fiven, the current session user will be used
     */
    public function addObjectFieldPermission($domainObject, $field, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a class. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed $domainObject
     * @param string $field
     * @param int $mask
     * @param UserInterface | ToekInterface | RoleInterface $securityIdentity if none fiven, the current session user will be used
     */
    public function addClassFieldPermission($domainObject, $field, $mask, $securityIdentity = null)

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

    /** Set permission mask for a given field of a domain object. All previous permissions
     * for this user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed $domainObject
     * @param string $field
     * @param int $mask
     * @param UserInterface | ToekInterface | RoleInterface $securityIdentity if none fiven, the current session user will be used
     */
    public function setObjectFieldPermission($domainObject, $field, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a class. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed $domainObject
     * @param string $field
     * @param int $mask
     * @param UserInterface | ToekInterface | RoleInterface $securityIdentity if none fiven, the current session user will be used
     */
    public function setClassFieldPermission($domainObject, $field, $mask, $securityIdentity = null)



    public function revokePermission($domainObject, $mask, $securityIdentity = null, $type = 'object');

    public function revokeFieldPermission($domainObject, $field, $mask, $securityIdentity = null, $type = 'object');

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

    /**
     * @param mixed $domainObject
     * @param string $field
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllObjectFieldPermissions($domainObject, $field, $securityIdentity = null);

    /**
     * @param mixed $domainObject
     * @param string $field
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllClassFieldPermissions($domainObject, $field, $securityIdentity = null);

    public function deleteAclFor($domainObject);

    public function isGranted($attributes, $object = null);

    public function isFieldGranted($attributes, $object = null);

    /**
     * Retrieves the current session user
     *
     * @return UserInterface
     */
    public function getUser();

}
