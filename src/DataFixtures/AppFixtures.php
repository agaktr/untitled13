<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class AppFixtures extends Fixture
{
    private UserPasswordHasherInterface $hasher;

    public const ADMIN_USER_REFERENCE = 'admin-user';
    public const USER_REFERENCE = 'user';

    public function __construct(UserPasswordHasherInterface $hasher)
    {
        $this->hasher = $hasher;
    }

    public function load(ObjectManager $manager)
    {
        //create a new admin fixture
        $userAdmin = new User();
        $userAdmin->setEmail('admin@admin.com');

        $password = $this->hasher->hashPassword($userAdmin, 'apassword28');
        $userAdmin->setPassword($password);
        $userAdmin->setIsVerified(true);
        $userAdmin->setRoles(['ROLE_ADMIN']);

        $manager->persist($userAdmin);

        //create a new user fixture
        $user = new User();
        $user->setEmail('user@user.com');

        $password = $this->hasher->hashPassword($user, 'apassword28');
        $user->setPassword($password);
        $user->setIsVerified(true);

        $manager->persist($user);

        //save the fixtures
        $manager->flush();

        // other fixtures can get this object using the UserFixtures::{TheReference} constant
        $this->addReference(self::ADMIN_USER_REFERENCE, $userAdmin);
        $this->addReference(self::USER_REFERENCE, $user);
    }
}
