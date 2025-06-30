<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AdminController;
use Illuminate\Support\Facades\Auth;

/*
|--------------------------------------------------------------------------
| Web Routes for BiteBarakah 🍰
|--------------------------------------------------------------------------
*/

// 🌟 Public Routes (no login required)
Route::get('/', function () {
    return Auth::check() ? redirect('/home') : redirect()->route('register');
});


Route::get('/home', function () {
    return view('home');
})->middleware('auth')->name('home');


Route::get('/order', function () {
    return view('order');
});

Route::get('/admin/orders', [AdminController::class, 'viewOrders'])->name('admin.orders')->middleware('auth');
Route::post('/order-submit', [OrderController::class, 'submit'])->name('order.submit');

// 🌟 Authenticated User Routes

    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    // 🌟 Admin Panel Routes (protected)
    Route::get('/admin', [AdminController::class, 'index'])->name('admin.index');
    Route::get('/admin/orders', [AdminController::class, 'viewOrders'])->name('admin.orders');
    Route::get('/admin/download-orders', [AdminController::class, 'downloadPDF'])->name('admin.downloadPDF');

// 🌟 Breeze Auth Routes (login, register, etc.)
require __DIR__.'/auth.php';
