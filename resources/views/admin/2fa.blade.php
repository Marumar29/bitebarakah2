<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800">Two-Factor Authentication (2FA)</h2>
    </x-slot>

    <div class="py-6 px-6 bg-white shadow rounded-lg">
        @if (session('status'))
            <div class="mb-4 text-green-600">{{ session('status') }}</div>
        @endif

        @if (auth()->user()->two_factor_secret)
            <p class="mb-4 text-green-700">✅ Two-factor authentication is currently <strong>enabled</strong>.</p>

            <p class="text-sm mt-2 text-gray-700">
                🔐 Your secret key (for Authenticator App setup):
                <span class="font-mono bg-gray-200 p-1 rounded">
                    {{ decrypt(auth()->user()->two_factor_secret) }}
                </span>
            </p>
            <p class="text-xs text-gray-500 mt-1">
                Open Google Authenticator, tap the + icon, then choose "Enter a setup key" and paste this key in.
            </p>

            <form method="POST" action="{{ route('admin.2fa.disable') }}">
                @csrf
                <x-primary-button>Disable 2FA</x-primary-button>
            </form>

            <div class="mt-6">
                <h3 class="text-sm font-bold">Recovery Codes:</h3>
                <ul class="mt-2 text-sm text-gray-700 bg-gray-100 p-2 rounded">
                    @foreach (json_decode(decrypt(auth()->user()->two_factor_recovery_codes)) as $code)
                        <li>{{ $code }}</li>
                    @endforeach
                </ul>
                <p class="text-xs mt-2 text-gray-500">Store these codes somewhere safe. They can be used if you lose access to your authenticator device.</p>
            </div>
        @else
            <p class="mb-4 text-gray-700">Two-factor authentication is currently <strong>disabled</strong>.</p>

            <form method="POST" action="{{ route('admin.2fa.enable') }}">
                @csrf
                <x-primary-button>Enable 2FA</x-primary-button>
            </form>
        @endif
    </div>
</x-app-layout>
