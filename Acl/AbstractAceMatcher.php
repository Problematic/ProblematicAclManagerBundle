<?php

namespace Problematic\AclManagerBundle\Acl;

use Problematic\AclManagerBundle\Model\AceMatcherInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;

abstract class AbstractAceMatcher implements AceMatcherInterface
{

    /**
     * @var AuditableEntryInterface
     */
    protected $ace;
    /**
     * @var PermissionContextInterface
     */
    protected $context;

    public function __construct(AuditableEntryInterface $ace = null, PermissionContextInterface $context = null)
    {
        $this->ace = $ace;
        $this->context = $context;
    }

    public function setAce(AuditableEntryInterface $ace)
    {
        $this->ace = $ace;
    }

    public function getAce()
    {
        return $this->ace;
    }

    public function setContext(PermissionContextInterface $context)
    {
        $this->context = $context;
    }

    public function getContext()
    {
        return $this->context;
    }

}
