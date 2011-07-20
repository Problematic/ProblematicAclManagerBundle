<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

interface PermissionContextInterface
{

    public function setMask($mask);

    public function getMask();

    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity);

    public function getSecurityIdentity();

    public function setPermissionType($type);

    public function getPermissionType();

    public function setGranting($granting);

    public function isGranting();
}

?>
