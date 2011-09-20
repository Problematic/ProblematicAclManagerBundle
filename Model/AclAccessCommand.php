<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Problematic\AclManagerBundle\Domain\PermissionContext;

class AclAccessCommand extends AclCommand
{
    
    private $access_type;
    
    public function __construct($access_type, AclCommandContextInterface $context, AclManagerInterface $manager)
    {
        parent::__construct($context, $manager);
        $this->access_type = strtolower($access_type);
        $this->getContext()->setAccessType($this->access_type);
    }

    public function to($mask)
    {
        $this->getContext()->setMask($mask);

        return new AclToCommand($this->getContext(), $this->getAclManager());
    }
    
}
