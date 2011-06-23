<?php

namespace Problematic\AclManagerBundle\Event;

use Symfony\Component\EventDispatcher\Event;

class FilterAclManagerEvent extends Event
{

    protected $entity;
    protected $identity;
    protected $mask;
    protected $installDefaults;
    
    public function __construct($entity, $identity, $mask = null, $installDefaults = false)
    {
        $this->entity = $entity;
        $this->identity = $identity;
        $this->mask = $mask;
        $this->installDefaults = $installDefaults;
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
    
    /**
     * Should default class permissions be installed on the ACL?
     * 
     * @return boolean
     */
    public function getInstallDefaults()
    {
        return $this->installDefaults;
    }

}
