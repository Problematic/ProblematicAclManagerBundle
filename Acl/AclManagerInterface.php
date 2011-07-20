<?php

namespace Problematic\AclManagerBundle\Acl;

interface AclManagerInterface
{

    public function loadAcl($entity);

    public function updateAcl();

    public function createSecurityIdentity($identity);

    public function createPermissionContext($type, $securityIdentity, $mask, $granting = true);

    public function addPermissionContext(PermissionContextInterface $permissionContext, $key = null);

    public function processPermissions($reset = false);

    public function applyPermission(PermissionContextInterface $permissionContext);
}
