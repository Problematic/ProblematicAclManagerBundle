<?php

namespace Problematic\AclManagerBundle\EventListener;

use Problematic\AclManagerBundle\Event\FilterAclManagerEvent,
    Problematic\AclManagerBundle\Acl\PermissionContext;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

class AclListener
{

    protected $manager;

    public function __construct($manager)
    {
        $this->manager = $manager;
    }

    public function onAclManage(FilterAclManagerEvent $event)
    {
        $this->loadAcl($event);
        $this->manager->processPermissions();
        if ($event->getInstallDefaults()) {
            $this->manager->installDefaults();
        }
    }
    
    private function loadAcl(FilterAclManagerEvent $event)
    {
        $identity = $this->loadPermissionContext($event);
        $this->manager->addPermissionContext($identity);
        $this->manager->loadAcl($event->getEntity());
    }
    
    private function loadPermissionContext(FilterAclManagerEvent $event)
    {
        $identity = $event->getIdentity();
        if (!$identity instanceof PermissionContext) {
            $mask = $event->getMask();
            if (null === $mask) {
                $mask = MaskBuilder::MASK_OPERATOR;
            }
            $identity = $this->manager->createPermissionContext('object', $identity, $mask);
        }
        
        return $identity;
    }

}
