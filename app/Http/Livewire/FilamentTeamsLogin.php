<?php

namespace App\Http\Livewire;

use DanHarrin\LivewireRateLimiting\Exceptions\TooManyRequestsException;
use DanHarrin\LivewireRateLimiting\WithRateLimiting;
use Filament\Forms\ComponentContainer;
use Filament\Forms\Components\Checkbox;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Livewire\Component;

/**
 * @property ComponentContainer $form
 */
class FilamentTeamsLogin extends Component implements HasForms
{
    use InteractsWithForms;
    use WithRateLimiting;

    public $email = '';

    public $password = '';

    public $remember = false;

    public function mount(): void
    {
        $guards = config('filament-teams.auth.guard');

        foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                redirect()->route('filament-teams.pages.dashboard');
            }
        }

        $this->form->fill();
    }

    public function authenticate(Request $request)
    {
        try {
            $this->rateLimit(5);
        } catch (TooManyRequestsException $exception) {
            throw ValidationException::withMessages([
                'email' => __('filament::login.messages.throttled', [
                    'seconds' => $exception->secondsUntilAvailable,
                    'minutes' => ceil($exception->secondsUntilAvailable / 60),
                ]),
            ]);
        }

        $data = $this->form->getState();

        $guards = config('filament-teams.auth.guard');

        foreach ($guards as $guard) {
            if (!Auth::guard($guard)->attempt([
                'email' => $data['email'],
                'password' => $data['password'],
            ], $data['remember'])) {
                throw ValidationException::withMessages([
                    'email' => __('filament::login.messages.failed'),
                ]);
            }
        }

        $request->session()->regenerate();
        return redirect()->route('filament-teams.pages.dashboard');
    }

    protected function getFormSchema(): array
    {
        return [
            TextInput::make('email')
                ->label(__('filament::login.fields.email.label'))
                ->email()
                ->required()
                ->autocomplete(),
            TextInput::make('password')
                ->label(__('filament::login.fields.password.label'))
                ->password()
                ->required(),
            Checkbox::make('remember')
                ->label(__('filament::login.fields.remember.label')),
        ];
    }

    public function render(): View
    {
        return view('filament::login')
            ->layout('filament::components.layouts.card', [
                'title' => __('Context Multiple Login'),
            ]);
    }
}
