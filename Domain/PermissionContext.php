<?php

namespace Problematic\AclManagerBundle\Domain;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Problematic\AclManagerBundle\Model\AclCommandContextInterface;

class PermissionContext implements PermissionContextInterface
{

    protected $permissionMask;
    protected $securityIdentity;
    protected $permissionType;
    protected $granting;

    public function __construct()
    {
        
    }

    /**
     * @param integer $mask permission mask, or null for all
     */
    public function setMask($mask)
    {
        $this->permissionMask = $mask;
    }

    public function getMask()
    {
        return $this->permissionMask;
    }

    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity)
    {
        $this->securityIdentity = $securityIdentity;
    }

    public function getSecurityIdentity()
    {
        return $this->securityIdentity;
    }

    public function setPermissionType($type)
    {
        $this->permissionType = $type;
    }

    public function getPermissionType()
    {
        return $this->permissionType;
    }

    public function setGranting($granting)
    {
        $this->granting = $granting;
    }

    public function isGranting()
    {
        return $this->granting;
    }
    
    public static function fromCommandContext(AclCommandContextInterface $commandContext)
    {
        $context = new self();
        $context->setSecurityIdentity($commandContext->getSecurityIdentity());
        $context->setPermissionType($commandContext->getPermissionType());
        $context->setMask($commandContext->getMask());
        $context->setGranting($commandContext->getAccessType() == 'permit' ? true : false);
        
        return $context;
    }
    
    public function equals(AuditableEntryInterface $ace)
    {
        return $ace->getSecurityIdentity() == $this->getSecurityIdentity() &&
            $ace->isGranting() === $this->isGranting() &&
            $ace->getMask() === $this->getMask();
    }

}
