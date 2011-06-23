<?php

namespace Problematic\AclManagerBundle\Event;

use Symfony\Component\EventDispatcher\Event;

class FilterAclManagerEvent extends Event
{

    protected $entity;
    protected $identity;
    protected $mask;
    
    public function __construct($entity, $identity, $mask = null)
    {
        $this->entity = $entity;
        $this->identity = $identity;
        $this->mask = $mask;
    }

    public function getEntity()
    {
        return $this->entity;
    }

    public function getMask()
    {
        return $this->mask;
    }
    
    public function getIdentity()
    {
        return $this->identity;
    }

}
