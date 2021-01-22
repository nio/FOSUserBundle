<?php
namespace Nio\UserBundle\Doctrine;

use FOS\UserBundle\Doctrine\UserManager as BaseUserManager;

use FOS\UserBundle\Model\UserInterface;
use FOS\UserBundle\Util\CanonicalizerInterface;
use FOS\UserBundle\Util\TokenGeneratorInterface;
use Nio\CMSBundle\Tools as CMSTools;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface as SecurityUserInterface;

use Symfony\Component\Security\Core\User\UserProviderInterface;


use Doctrine\ORM\EntityManagerInterface;
use FOS\UserBundle\Util\CanonicalFieldsUpdater;
use FOS\UserBundle\Util\PasswordUpdaterInterface;

// TODO: should this better extend from Model/UserManager instead of Doctrine/UserManager, as stated here:
// http://symfony.com/doc/current/bundles/FOSUserBundle/user_manager.html ???
class UserManager extends BaseUserManager
{
    //private $passwordUpdater;
    private $canonicalFieldsUpdater;
    private $tokenGenerator;


    public function __construct(PasswordUpdaterInterface $passwordUpdater, CanonicalFieldsUpdater $canonicalFieldsUpdater, EntityManagerInterface $om, $class, TokenGeneratorInterface $tokenGenerator)
    {
        parent::__construct($passwordUpdater, $canonicalFieldsUpdater, $om, $class);

        //$this->passwordUpdater = $passwordUpdater;
        $this->canonicalFieldsUpdater = $canonicalFieldsUpdater;
        $this->tokenGenerator = $tokenGenerator;
    }


    // email is not unique model-wise. make sure to only return users by email if unique ...
    public function findUserByEmail($email)
    {
        $users = $this->getRepository()->findBy(array('emailCanonical' => $this->canonicalFieldsUpdater->canonicalizeEmail($email)));

        if (1 == count($users)) {
            return $users[0];
        }

        // No or multiple users where found.
        return null;
    }

    // corresponding method in FOS\UserBundle\Model\UserManager was not checking if usernameOrEmail is a username first.
    public function findUserByUsernameOrEmail($usernameOrEmail)
    {
        if (filter_var($usernameOrEmail, FILTER_VALIDATE_EMAIL)) {
            $user = $this->findUserByUsername($usernameOrEmail);
            if ($user) {
                return $user;
            } else {
                return $this->findUserByEmail($usernameOrEmail);
            }
        }

        return $this->findUserByUsername($usernameOrEmail);
    }

    public function disableAndCreateConfirmationToken(UserInterface $user)
    {
        $user->setEnabled(false);
        $user->setConfirmationToken($this->tokenGenerator->generateToken());
        if ($user->getNutzungsbedingung()) {
            $user->setDatenschutzbestimmung(true);
        }
        $this->updateUser($user, true);
    }

    public function getUniqueUsername($username, $iterate = true)
    {
        $username = CMSTools::slugify($username);
        $username = preg_replace("/[^a-zA-Z0-9\-]/", "", $username);
        $username = substr($username, 0, 30);

        $ret = $username;

        if (false === $iterate) {
            if ($this->findUserByUsername($ret)) {
                return false;
            } else {
                return $ret;
            }
        } else {
            $i = 2;
            while ($this->findUserByUsername($ret)) {
                $ret = $username.'-'.$i;
                $i++;
            }
            return $ret;
        }
    }


    # used in HWIOAuth Registration (because findUserByEmail returns null on multiple results)
    public function existsEmail($email)
    {
        $users = $this->getRepository()->findBy(array('emailCanonical' => $this->canonicalFieldsUpdater->canonicalizeEmail($email)));

        return (0 < count($users)) ? true : false;
    }
}
