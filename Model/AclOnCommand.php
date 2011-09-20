<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Problematic\AclManagerBundle\Domain\PermissionContext;

class AclOnCommand extends AclCommand
{
    
    public function flush()
    {
        $manager = $this->getAclManager();
        $acl = $manager->loadAcl($this->getContext()->getObjectIdentity());
        $permissionContext = PermissionContext::fromCommandContext($this->getContext());
        
        switch ($this->getContext()->getAccessType()) {
            case 'permit':
                $manager->addPermission($acl, $permissionContext);
                break;
            case 'deny':
                $manager->revokePermission($acl, $permissionContext);
                break;
            case 'remove':
                $manager->revokeAllPermissions($acl, $permissionContext);
                break;
            default:
        }
        
        $manager->getAclProvider()->updateAcl($acl);
        
        return $this->getAclManager();
    }

}
