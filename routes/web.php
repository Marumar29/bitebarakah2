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

// 🌟 User Order History
Route::get('/my-orders', [OrderController::class, 'myOrders'])->middleware('auth')->name('orders.mine');

// 🌟 Admin Panel
Route::get('/admin', [AdminController::class, 'index'])->name('admin.index');
Route::get('/admin/orders', [AdminController::class, 'viewOrders'])->name('admin.orders')->middleware('auth');
Route::get('/admin/download-orders', [AdminController::class, 'downloadPDF'])->name('admin.downloadPDF');

// 🌟 User Profile (Breeze)
Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

// 🌟 Auth routes (login, register, etc.)
require __DIR__.'/auth.php';
