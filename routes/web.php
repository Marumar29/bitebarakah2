<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AdminController;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str; // Needed for 2FA
use PragmaRX\Google2FA\Google2FA;

/*
|--------------------------------------------------------------------------
| Web Routes for BiteBarakah 🍰
|--------------------------------------------------------------------------
*/

// 🌟 Public Root Redirect
Route::get('/', function () {
    return Auth::check() ? redirect()->route('home') : redirect()->route('register');
});

// 🌟 Authenticated Home Page (used in nav as 'home')
Route::get('/home', function () {
    return view('home');
})->middleware('auth')->name('home');

// 🌟 Order Page (public)
Route::get('/order', function () {
    return view('order');
});

// 🌟 Order Submission (POST)
Route::post('/order-submit', [OrderController::class, 'submit'])->name('order.submit');

// 🌟 Breeze Auth Routes (login, register, etc.)
require __DIR__.'/auth.php';

// 🌟 Authenticated User Routes
Route::middleware(['auth'])->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    // 🌟 User Order History
    Route::get('/my-orders', [OrderController::class, 'myOrders'])->name('orders.mine');
});

// 🌟 Admin Panel Routes (protected with is_admin)
Route::middleware(['auth', 'is_admin'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index'])->name('admin.index');
    Route::get('/admin/orders', [AdminController::class, 'viewOrders'])->name('admin.orders');
    Route::get('/admin/download-orders', [AdminController::class, 'downloadPDF'])->name('admin.downloadPDF');

    // ✅ 2FA Management
    Route::get('/admin/2fa', function () {
        return view('admin.2fa');
    })->name('admin.2fa');

    Route::post('/admin/2fa/enable', function () {
        $user = auth()->user();
        $google2fa = new Google2FA();

        $user->forceFill([
            'two_factor_secret' => encrypt($google2fa->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(
                collect(range(1, 8))->map(fn () => Str::random(10))->all()
            )),
        ])->save();

        return back()->with('status', '2FA enabled. Store your recovery codes.');
    })->name('admin.2fa.enable');

    Route::post('/admin/2fa/disable', function () {
        $user = auth()->user();
        $user->forceFill([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
        ])->save();

        return back()->with('status', '2FA disabled.');
    })->name('admin.2fa.disable');
});

// 🌟 Dashboard redirects to Home (for Fortify compatibility)
Route::get('/dashboard', function () {
    return redirect('/home');
})->middleware('auth')->name('dashboard');
