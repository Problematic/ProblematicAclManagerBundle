<?php

namespace Problematic\AclManagerBundle\Model;

interface AclManagerInterface
{

    function permit($user);
    
    function deny($user);
    
}
