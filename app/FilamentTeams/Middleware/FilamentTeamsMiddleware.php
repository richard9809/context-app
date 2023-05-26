<?php

namespace App\FilamentTeams\Middleware;

use Filament\Models\Contracts\FilamentUser;
use Illuminate\Auth\Middleware\Authenticate as Middleware;

class FilamentTeamsMiddleware extends Middleware
{
    protected function authenticate($request, array $guards): void
    {
        $guardNames = config('filament-teams.auth.guard');

        foreach ($guardNames as $guardName) {
            $guard = $this->auth->guard($guardName);

            if ($guard->check()) {
                $this->auth->shouldUse($guardName);
    
                $user = $guard->user();
    
                if ($user instanceof FilamentUser) {
                    abort_if(!$user->canAccessFilament(), 403);
    
                    return;
                }
    
                abort_if(config('app.env') !== 'local', 403);
            }
        }

        $this->unauthenticated($request, $guards);
    }

    protected function redirectTo($request): string
    {
        return route('filament-teams.auth.login');
    }
}
