<?php

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Enum;

enum ProviderEnum: string
{
    case IDENTITY_PROVIDER_APPLE = 'apple.com';
    case IDENTITY_PROVIDER_GOOGLE = 'google.com';
    case IDENTITY_PROVIDER_FIREBASE = 'firebase.com';
}
