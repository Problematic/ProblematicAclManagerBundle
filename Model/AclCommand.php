<?php

namespace Problematic\AclManagerBundle\Model;

class AclCommand implements AclCommandInterface
{

    private $context;
    private $manager;
    
    public function __construct(AclCommandContextInterface $context, AclManagerInterface $manager)
    {
        $this->context = $context;
        $this->manager = $manager;
    }
    
    /**
     * @return AclCommandContextInterface
     */
    protected function getContext()
    {
        return $this->context;
    }
    
    /**
     * @return AclManagerInterface
     */
    protected function getAclManager()
    {
        return $this->manager;
    }
    
    /**
     * @return AclManagerInterface
     */
    public function cancel()
    {
        return $this->manager;
    }

}
