<?php

namespace Problematic\AclManagerBundle\Model;

interface AclCommandInterface
{

    function getContext();
    
    function getAclManager();

}
